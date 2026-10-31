package com.aegislens.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * IP addresses marked as blocked. AegisLens never touches the firewall: this list is exported as a blocklist file
 * and ready-made firewall commands.
 */
public class BlockedIpRepository extends BaseRepository<BlockedIp, String> implements Repository<BlockedIp, String> {

    public BlockedIpRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "blocked_ip";
    }

    /** Blocks an IP now (or updates the reason if it is already blocked). */
    public void block(String ip, String reason) throws SQLException {
        save(new BlockedIp(ip, reason, Instant.now()));
    }

    /** Removes the block. Returns false if the IP was not blocked. */
    public boolean unblock(String ip) throws SQLException {
        return update("DELETE FROM blocked_ip WHERE ip = ?", ps -> ps.setString(1, ip)) == 1;
    }

    public boolean isBlocked(String ip) throws SQLException {
        return findById(ip).isPresent();
    }

    @Override
    public void save(BlockedIp item) throws SQLException {
        update("INSERT INTO blocked_ip (ip, reason, blocked_at) VALUES (?, ?, ?) "
                + "ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason", ps -> {
            ps.setString(1, item.ip());
            ps.setString(2, item.reason());
            ps.setString(3, iso(item.blockedAt()));
        });
    }

    @Override
    public Optional<BlockedIp> findById(String ip) throws SQLException {
        return queryOne("SELECT * FROM blocked_ip WHERE ip = ?", ps -> ps.setString(1, ip), BlockedIpRepository::map);
    }

    /** All blocked IPs, newest first. */
    @Override
    public List<BlockedIp> findAll() throws SQLException {
        return queryList("SELECT * FROM blocked_ip ORDER BY blocked_at DESC, ip", NO_PARAMS, BlockedIpRepository::map);
    }

    @Override
    public void delete(String ip) throws SQLException {
        unblock(ip);
    }

    private static BlockedIp map(ResultSet rs) throws SQLException {
        return new BlockedIp(rs.getString("ip"), rs.getString("reason"), instant(rs, "blocked_at"));
    }
}
