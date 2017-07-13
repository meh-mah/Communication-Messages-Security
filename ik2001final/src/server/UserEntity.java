/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.io.Serializable;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;

/**
 *
 * @author M&M
 */
@NamedQueries({
    @NamedQuery(name = UserEntity.GET_USER_BY_ID_QUERY,
    query = "SELECT u "
    + "FROM UserEntity u "
    + "WHERE u.id = :id"),
    @NamedQuery(name = UserEntity.GET_USER_BY_NAME_QUERY,
    query = "SELECT u "
    + "FROM UserEntity u "
    + "WHERE u.name = :name")
        })
@Entity
public class UserEntity implements Serializable {
    private static final long serialVersionUID = 1L;
    public static final String GET_USER_BY_ID_QUERY = "UserEntity_getUserById";
    public static final String GET_USER_BY_NAME_QUERY = "UserEntity_getUserByName";
    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column(name = "name", nullable = false)
    private String name;
    @Column(name = "password", nullable = false)
    private int password;

    /*Constructors*/
    public UserEntity() {
    }

    public UserEntity(String name, int password) {
        this.name = name;
        this.password = password;
    }

    /*Getters and setters*/
    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public int getPassword() {
        return password;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setPassword(int password) {
        this.password = password;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof UserEntity)) {
            return false;
        }
        UserEntity other = (UserEntity) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "client.CatalogUser[ id=" + id + " ]";
    }
    
}
