/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package exception;

/**
 *
 * @author M&M
 */
public class AlreadyLoggedInException extends RejectedException {
    Long id;

    public AlreadyLoggedInException(String reason, Long id) {
        super(reason);
        this.id = id;
    }

    public Long getId() {
        return id;
    }
}

