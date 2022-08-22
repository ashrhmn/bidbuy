package dao;

import lombok.RequiredArgsConstructor;
import model.EmailVerificationToken;
import org.hibernate.SessionFactory;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class EmailVerificationDao {
    private final SessionFactory sessionFactory;

    public void addEmailToken(EmailVerificationToken emailVerificationToken) {
        this.sessionFactory.getCurrentSession().save(emailVerificationToken);
    }

    public EmailVerificationToken getOne(int id) {
        try {
            return this.
                    sessionFactory.
                    getCurrentSession().
                    createQuery(
                            "FROM EmailVerificationToken where id=:id",
                            EmailVerificationToken.class
                    ).setParameter("id", id).getSingleResult();
        } catch (Exception e) {
            return null;
        }
    }

    public EmailVerificationToken getByToken(String token) {
        try {
            return this.
                    sessionFactory.
                    getCurrentSession().
                    createQuery(
                            "FROM EmailVerificationToken where token=:token",
                            EmailVerificationToken.class
                    ).setParameter("token", token).getSingleResult();
        } catch (Exception e) {
            return null;
        }
    }

    public String deleteEmailToken(int id) {
        try {
            EmailVerificationToken emailVerificationToken = this.
                    sessionFactory.
                    getCurrentSession().
                    createQuery(
                            "FROM EmailVerificationToken where id=:id",
                            EmailVerificationToken.class
                    ).setParameter("id", id).getSingleResult();
            this.sessionFactory.getCurrentSession().delete(emailVerificationToken);
            return "deleted";
        } catch (Exception e) {
            return "Not Found";
        }
    }
}
