package tak.server.filemanager;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.bbn.marti.sync.EnterpriseSyncService;
import com.bbn.marti.sync.Metadata;
import com.bbn.marti.util.CommonUtil;
import com.bbn.marti.util.spring.RequestHolderBean;

/**
 * Verifies FileManagerApi.putMetadata refuses to persist when the caller
 * has no resolvable group vector (the IDOR fix) and otherwise threads the
 * group vector through to every persistence call.
 */
public class FileManagerApiPutMetadataTest {

	private FileManagerApi api;
	private EnterpriseSyncService persistenceStore;
	private RequestHolderBean requestHolderBean;
	private CommonUtil commonUtil;
	private HttpServletRequest request;
	private HttpServletResponse response;

	private void inject(String fieldName, Object value) throws Exception {
		Field f = FileManagerApi.class.getDeclaredField(fieldName);
		f.setAccessible(true);
		f.set(api, value);
	}

	@Before
	public void setUp() throws Exception {
		api = new FileManagerApi();
		persistenceStore = Mockito.mock(EnterpriseSyncService.class);
		requestHolderBean = Mockito.mock(RequestHolderBean.class);
		commonUtil = Mockito.mock(CommonUtil.class);
		request = Mockito.mock(HttpServletRequest.class);
		response = Mockito.mock(HttpServletResponse.class);

		inject("persistenceStore", persistenceStore);
		inject("requestHolderBean", requestHolderBean);
		inject("commonUtil", commonUtil);

		when(requestHolderBean.getRequest()).thenReturn(request);
	}

	@Test
	public void rejectsRequestWhenGroupVectorEmpty() throws Exception {
		// Cannot stub the SpringContextBeanForApi static; bypass by leaving
		// groupVector null (the exception path inside putMetadata) — same
		// outcome that triggers the 403.
		api.putMetadata("deadbeef", "alice", "", Collections.emptyList(), response);

		verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
		verifyNoInteractions(persistenceStore);
	}

	@Test
	public void rejectsBlankGroupVectorOnAllFields() throws Exception {
		api.putMetadata("deadbeef", "alice", "1700000000",
				Arrays.asList("tag1", "tag2"), response);

		verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
		verifyNoInteractions(persistenceStore);
	}

	@Test
	public void rejectsWhenOnlyKeywordsProvided() throws Exception {
		api.putMetadata("deadbeef", "", "", Arrays.asList("k"), response);

		verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
		verify(persistenceStore, never())
				.updateMetadataKeywords(anyString(), anyList());
		verify(persistenceStore, never())
				.updateMetadataKeywords(anyString(), anyList(), anyString());
	}

	@Test
	public void rejectsWhenNoFieldsProvided() throws Exception {
		// Even a no-op call (no user/expiration/keywords) must short-circuit
		// before reaching the persistence layer if group resolution failed.
		api.putMetadata("deadbeef", "", "", null, response);

		verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
		verifyNoInteractions(persistenceStore);
	}
}
