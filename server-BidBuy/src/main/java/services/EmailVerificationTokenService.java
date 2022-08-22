package services;

import dao.EmailVerificationDao;
import lombok.RequiredArgsConstructor;
import model.EmailVerificationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class EmailVerificationTokenService {
    private final EmailVerificationDao emailVerificationDao;

    public void addToken(EmailVerificationToken emailVerificationToken) {
        emailVerificationDao.addEmailToken(emailVerificationToken);
    }

    public void deleteToken(int id) {
        emailVerificationDao.deleteEmailToken(id);
    }

    public EmailVerificationToken getOne(int id) {
        return emailVerificationDao.getOne(id);
    }

    public EmailVerificationToken getByToken(String token) {
        return emailVerificationDao.getByToken(token);
    }
}
