/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.NoResultException;
import javax.persistence.Persistence;
import exception.AlreadyLoggedInException;
import exception.RejectedException;


public class LogModule {
    private final EntityManager em = Persistence.createEntityManagerFactory("PU").createEntityManager();
    private Set<Long> loggedInUsers = new HashSet<>();
    private final static UserEntity UNKNOWN = new UserEntity("<UNKNOWN>", 0);

    public LogModule() {

        EntityTransaction transaction = null;
        try {
            transaction = beginTransaction();
            List<UserEntity> users = em.createNamedQuery(UserEntity.GET_USER_BY_NAME_QUERY, UserEntity.class).
                    setParameter("name", UNKNOWN.getName()).
                    getResultList();
            if (users.isEmpty()) {
                em.persist(UNKNOWN);
            }

        } finally {
            commitTransaction(transaction);
        }
    }


    public void registerUser(String name, String password) throws RejectedException {
        EntityTransaction transaction = null;
        try {
            transaction = beginTransaction();

            List<UserEntity> users = em.createNamedQuery(UserEntity.GET_USER_BY_NAME_QUERY, UserEntity.class).
                    setParameter("name", name).
                    getResultList();
            if (!users.isEmpty()) {
                throw new RejectedException("Account exists");
            }

            UserEntity newUser = new UserEntity(name, password.hashCode());
            em.persist(newUser);
        } finally {
            commitTransaction(transaction);
        }
    }


    public Long login(String name, String password) throws AlreadyLoggedInException, RejectedException{

        UserEntity user;
        try {
            user = em.createNamedQuery(UserEntity.GET_USER_BY_NAME_QUERY, UserEntity.class).
                    setParameter("name", name).
                    getSingleResult();
        } catch (NoResultException ex) {
            user = null;
        }

        if ((user == null) || (user.getPassword() != password.hashCode())) {
            throw new RejectedException("Wrong user name or password");
        }

        if (loggedInUsers.add(user.getId()) == false) {
            throw new AlreadyLoggedInException("Already logged in!", user.getId());
        } else {
            return user.getId();
        }

    }

    public void logout(Long id) throws RejectedException {
        if (!loggedInUsers.contains(id)) {
            throw new RejectedException("Not logged in!");
        }

        loggedInUsers.remove(id);

    }

    private EntityTransaction beginTransaction() {
        EntityTransaction transaction = em.getTransaction();
        transaction.begin();
        return transaction;
    }

    private void commitTransaction(EntityTransaction transaction) {
        transaction.commit();
    }

}