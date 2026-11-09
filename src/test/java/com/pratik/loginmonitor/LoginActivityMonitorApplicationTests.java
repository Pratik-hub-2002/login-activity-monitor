package com.pratik.loginmonitor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:loginactivitytest;DB_CLOSE_DELAY=-1;MODE=MySQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
class LoginActivityMonitorApplicationTests {

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

	@Test
	void contextLoads() {
	}

    @Test
    @Transactional
    void recentAttemptQueryExcludesOutOfWindowRowsAndBoundsFailuresBeforeSuccess() {
        LocalDateTime successTime = LocalDateTime.of(2026, 11, 9, 12, 0);
        LocalDateTime cutoff = successTime.minusMinutes(10);

        loginAttemptRepository.save(new LoginAttempt(
                null, "ordered-user", "192.0.2.1",
                cutoff.minusMinutes(1), LoginStatus.FAILURE));
        loginAttemptRepository.save(new LoginAttempt(
                null, "ordered-user", "192.0.2.1",
                cutoff.plusMinutes(1), LoginStatus.FAILURE));
        loginAttemptRepository.save(new LoginAttempt(
                null, "ordered-user", "192.0.2.1",
                cutoff.plusMinutes(2), LoginStatus.FAILURE));
        loginAttemptRepository.save(new LoginAttempt(
                null, "ordered-user", "192.0.2.1",
                cutoff.plusMinutes(3), LoginStatus.FAILURE));
        loginAttemptRepository.save(new LoginAttempt(
                null, "ordered-user", "192.0.2.1",
                successTime, LoginStatus.SUCCESS));
        loginAttemptRepository.save(new LoginAttempt(
                null, "ordered-user", "192.0.2.1",
                successTime.plusMinutes(1), LoginStatus.FAILURE));
        loginAttemptRepository.flush();

        List<LoginAttempt> recent =
                loginAttemptRepository.findByAttemptTimeAfterOrderByAttemptTimeAsc(cutoff);
        assertEquals(5, recent.size());
        assertEquals(cutoff.plusMinutes(1), recent.get(0).getAttemptTime());

        long precedingFailures =
                loginAttemptRepository
                        .countByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                                "ordered-user",
                                LoginStatus.FAILURE,
                                cutoff,
                                successTime);
        assertEquals(3L, precedingFailures);
    }
}
