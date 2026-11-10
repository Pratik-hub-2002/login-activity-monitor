package com.pratik.loginmonitor.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDateTime;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;

@DataJpaTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:suspiciousfingerprinttest;DB_CLOSE_DELAY=-1;MODE=MySQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class SuspiciousActivityRepositoryConcurrencyTest {

    private static final Pattern FINGERPRINT_CONSTRAINT_PATTERN = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9_])"
                    + Pattern.quote(SuspiciousActivity.DETECTION_FINGERPRINT_UNIQUE_CONSTRAINT)
                    + "(?:$|[^A-Z0-9_])");

    @Autowired
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void concurrentInsertsWithSameFingerprintPersistOnlyOneRecord()
            throws InterruptedException, ExecutionException, java.util.concurrent.TimeoutException {
        String fingerprint = "a".repeat(64);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

        try {
            Future<Boolean> first = executor.submit(
                    () -> insertAfterStart(fingerprint, ready, start, transaction));
            Future<Boolean> second = executor.submit(
                    () -> insertAfterStart(fingerprint, ready, start, transaction));

            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            boolean firstInserted = first.get(10, TimeUnit.SECONDS);
            boolean secondInserted = second.get(10, TimeUnit.SECONDS);

            assertTrue(firstInserted ^ secondInserted);
            assertEquals(1, suspiciousActivityRepository.count());
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    private boolean insertAfterStart(
            String fingerprint,
            CountDownLatch ready,
            CountDownLatch start,
            TransactionTemplate transaction) throws InterruptedException {
        ready.countDown();
        if (!start.await(5, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Concurrent insert start timed out.");
        }

        try {
            transaction.executeWithoutResult(status ->
                    suspiciousActivityRepository.saveAndFlush(
                            new SuspiciousActivity(
                                    null,
                                    "concurrent-user",
                                    "192.0.2.1",
                                    SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME,
                                    "Concurrent uniqueness test",
                                    LocalDateTime.now(),
                                    fingerprint)));
            return true;
        } catch (DataIntegrityViolationException expectedDuplicate) {
            if (!isFingerprintConstraintViolation(expectedDuplicate)) {
                throw expectedDuplicate;
            }
            return false;
        }
    }

    private boolean isFingerprintConstraintViolation(Throwable exception) {
        Throwable cause = exception;
        while (cause != null) {
            if (cause instanceof ConstraintViolationException violation) {
                String constraintName = violation.getConstraintName();
                return constraintName != null
                        && FINGERPRINT_CONSTRAINT_PATTERN.matcher(constraintName).find();
            }
            if (cause.getCause() == cause) {
                break;
            }
            cause = cause.getCause();
        }
        return false;
    }
}
