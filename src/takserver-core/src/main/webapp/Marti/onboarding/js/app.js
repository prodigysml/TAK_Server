(function() {
  'use strict';

  // Admin onboarding portal. Reuses the same admin session/auth as the rest
  // of the TAK admin UI. Cert passwords are kept ONLY in sessionStorage so a
  // tab reload preserves them (admin can download a pack after creating)
  // but closing the tab forgets them. Nothing is persisted server-side.
  var app = angular.module('onboardingManager', []);

  app.controller('OnboardingController', ['$scope', '$http', function($scope, $http) {
    $scope.users = [];
    $scope.newUsername = '';
    $scope.serverHost = 'server.aevogrid.com';
    $scope.status = '';
    $scope.statusError = false;
    $scope.lastCreated = null;

    function setStatus(msg, isError) {
      $scope.status = msg || '';
      $scope.statusError = !!isError;
    }

    function rememberPass(user, pass) {
      try { sessionStorage.setItem('certPass:' + user, pass); } catch (e) {}
    }
    function recallPass(user) {
      try { return sessionStorage.getItem('certPass:' + user) || ''; } catch (e) { return ''; }
    }
    function forgetPass(user) {
      try { sessionStorage.removeItem('certPass:' + user); } catch (e) {}
    }

    $scope.refresh = function() {
      setStatus('Loading...');
      $http.get('/Marti/api/onboarding/users').then(function(resp) {
        $scope.users = (resp.data && resp.data.data) || [];
        setStatus('');
      }, function(err) {
        setStatus('Failed to load users (HTTP ' + err.status + ')', true);
      });
    };

    $scope.createUser = function() {
      var u = ($scope.newUsername || '').trim();
      if (!/^[A-Za-z0-9_-]{1,32}$/.test(u)) {
        setStatus('Username must match ^[A-Za-z0-9_-]{1,32}$', true);
        return;
      }
      setStatus('Creating cert for ' + u + ' (takes ~10s)...');
      $scope.lastCreated = null;
      $http.post('/Marti/api/onboarding/users', { username: u },
                 { headers: { 'Content-Type': 'application/json' } })
        .then(function(resp) {
          var d = resp.data && resp.data.data;
          if (!d) { setStatus('Empty response', true); return; }
          rememberPass(d.username, d.certPass);
          $scope.lastCreated = d;
          setStatus('');
          $scope.newUsername = '';
          $scope.refresh();
        }, function(err) {
          var msg = (err.data && err.data.message) || err.statusText || ('HTTP ' + err.status);
          setStatus('Create failed: ' + msg, true);
        });
    };

    $scope.downloadPack = function(username, platform) {
      var certPass = recallPass(username);
      if (!certPass) {
        certPass = prompt('Cert password for ' + username + ' (from when it was created):');
        if (!certPass) return;
        rememberPass(username, certPass);
      }
      var host = ($scope.serverHost || '').trim();
      if (!host) { setStatus('Server host required', true); return; }
      setStatus('Building ' + platform + ' pack for ' + username + '...');

      $http.post(
        '/Marti/api/onboarding/users/' + encodeURIComponent(username) +
          '/datapackage/' + platform,
        { certPass: certPass, host: host },
        { responseType: 'blob', headers: { 'Content-Type': 'application/json' } }
      ).then(function(resp) {
        setStatus('');
        var url = window.URL.createObjectURL(resp.data);
        var a = document.createElement('a');
        a.href = url;
        a.download = username + '-' + platform + '.zip';
        document.body.appendChild(a);
        a.click();
        setTimeout(function() {
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
        }, 100);
      }, function(err) {
        setStatus('Download failed (HTTP ' + err.status + '). Wrong cert password?', true);
      });
    };

    $scope.revoke = function(username) {
      if (!confirm('Revoke ' + username +
                   '? Cert goes on CRL, user removed, EFS cert files deleted. Cannot be undone.')) return;
      setStatus('Revoking ' + username + '...');
      $http.delete('/Marti/api/onboarding/users/' + encodeURIComponent(username))
        .then(function() {
          setStatus(username + ' revoked.');
          forgetPass(username);
          $scope.refresh();
        }, function(err) {
          setStatus('Revoke failed (HTTP ' + err.status + ')', true);
        });
    };

    $scope.refresh();
  }]);
})();
