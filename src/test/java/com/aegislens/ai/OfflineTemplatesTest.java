package com.aegislens.ai;

import com.aegislens.db.Database;
import com.aegislens.db.RuleRepository;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Every rule in the seeded rule table has its own offline explanation (no rule falls back to the generic text). */
class OfflineTemplatesTest {

    @Test
    void everySeededRuleHasAnOfflineTemplate() throws Exception {
        try (Database db = Database.inMemory()) {
            List<String> missing = new RuleRepository(db).findAll().stream()
                    .map(r -> r.id())
                    .filter(id -> OfflineProvider.class.getResource("/templates/" + id + ".txt") == null)
                    .toList();
            assertEquals(List.of(), missing, "add src/main/resources/templates/<rule>.txt for these rules");
        }
    }
}
