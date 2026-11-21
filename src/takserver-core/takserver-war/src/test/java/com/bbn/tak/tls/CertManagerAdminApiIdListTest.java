package com.bbn.tak.tls;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

public class CertManagerAdminApiIdListTest {

    @Test
    public void parsesIds() {
        assertEquals(Arrays.asList(1L, 22L, 333L), CertManagerAdminApi.parseIdList("1,22,333", 100));
    }

    @Test
    public void ignoresTrailingCommaFromAdminUi() {
        assertEquals(Arrays.asList(1L, 2L), CertManagerAdminApi.parseIdList("1,2,", 100));
        assertEquals(3, CertManagerAdminApi.parseIdList("1,2,3,", 3).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsOnlyCommas() {
        CertManagerAdminApi.parseIdList(",,", 100);
    }

    @Test
    public void acceptsExactlyMax() {
        assertEquals(3, CertManagerAdminApi.parseIdList("1,2,3", 3).size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsMoreThanMax() {
        CertManagerAdminApi.parseIdList("1,2,3,4", 3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsHugeListWithoutParsingAll() {
        StringBuilder sb = new StringBuilder("1");
        for (int i = 0; i < 100_000; i++) {
            sb.append(",1");
        }
        CertManagerAdminApi.parseIdList(sb.toString(), CertManagerAdminApi.MAX_BULK_IDS);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsNonNumeric() {
        CertManagerAdminApi.parseIdList("1,abc", 100);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsEmptyEntry() {
        CertManagerAdminApi.parseIdList("1,,2", 100);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsEmpty() {
        CertManagerAdminApi.parseIdList("", 100);
    }

    @Test
    public void defaultCaps() {
        assertEquals(100, CertManagerAdminApi.MAX_BULK_IDS);
        assertEquals(50, CertManagerAdminApi.MAX_REVOKE_IDS);
    }
}
