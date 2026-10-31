package com.aegislens.db;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * Generic CRUD contract: T is the entity type and ID its key type (two type parameters).
 */
public interface Repository<T, ID> {

    void save(T item) throws SQLException;

    Optional<T> findById(ID id) throws SQLException;

    List<T> findAll() throws SQLException;

    void delete(ID id) throws SQLException;
}
