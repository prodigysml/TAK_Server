package com.bbn.marti.feeds;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.List;
import java.util.concurrent.Callable;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.Test;

import com.bbn.marti.remote.exception.NotFoundException;
import com.bbn.marti.remote.util.RemoteUtil;
import com.bbn.marti.sync.repository.DataFeedRepository;
import com.bbn.marti.util.CommonUtil;

import tak.server.feeds.DataFeedDTO;

/**
 * Guard test for {@link DataFeedApi#deletePredicateDataFeed} (ZeroPath cluster
 * #5, issue 21702cbd). The feed is validated to exist and be group-accessible,
 * then deleted via a conditional DELETE whose returned id was discarded. A null
 * result (the feed was removed concurrently) must surface as NotFoundException
 * rather than a success response built from the stale pre-read feed.
 *
 * <p>The companion update endpoint takes the same fix; it is exercised by the
 * same pattern but its repository call has 24 parameters, so it is covered by
 * compilation + the war regression suite rather than a brittle 24-matcher stub.
 */
public class DataFeedApiDeleteGuardTest {

	private static void inject(Object target, String field, Object value) throws Exception {
		Field f = target.getClass().getDeclaredField(field);
		f.setAccessible(true);
		f.set(target, value);
	}

	@Test
	public void deletePredicateDataFeed_whenDeleteMatchesNoRow_throwsNotFound() throws Exception {
		DataFeedApi api = new DataFeedApi();
		DataFeedRepository repo = mock(DataFeedRepository.class);
		RemoteUtil remoteUtil = mock(RemoteUtil.class);
		CommonUtil commonUtil = mock(CommonUtil.class);
		HttpServletRequest request = mock(HttpServletRequest.class);

		inject(api, "dataFeedRepository", repo);
		inject(api, "remoteUtil", remoteUtil);
		inject(api, "commonUtil", commonUtil);
		inject(api, "request", request);

		String feedUuid = "feed-uuid-1";
		DataFeedDTO dto = mock(DataFeedDTO.class);
		when(dto.getGroupVector()).thenReturn("feed-gv");

		when(remoteUtil.bitVectorToString(any())).thenReturn("caller-gv");
		when(repo.doesFeedExist(feedUuid)).thenReturn(true);
		when(repo.getDataFeedByUUID(feedUuid)).thenReturn(List.of(dto));
		when(remoteUtil.isGroupVectorAllowed(any(), any())).thenReturn(true);
		// the feed vanished between validation and delete -> no row deleted
		when(repo.deleteDataFeedByUuid(feedUuid)).thenReturn(null);

		Callable<?> deletion = api.deletePredicateDataFeed(feedUuid);
		try {
			deletion.call();
			fail("expected NotFoundException when the delete matched no row");
		} catch (NotFoundException expected) {
			// pass
		}
	}
}
