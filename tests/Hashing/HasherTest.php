<?php

namespace Illuminate\Tests\Hashing;

use Illuminate\Config\Repository as Config;
use Illuminate\Container\Container;
use Illuminate\Hashing\Argon2IdHasher;
use Illuminate\Hashing\ArgonHasher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Hashing\HashManager;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class HasherTest extends TestCase
{
    /**
     * The hash manager instance.
     *
     * @var  HashManager  $hashManager
     */
    public $hashManager;

    /**
     * Setup the test environment.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $setUpContainer = (Container::setInstance(container: new Container));

        $setUpContainer->singleton(abstract: 'config', concrete: fn() => new Config());

        $this->hashManager = new HashManager(container: $setUpContainer);
    }

    /**
     * Provide hashers for testing.
     *
     * @return array<array{0: BcryptHasher|ArgonHasher|Argon2IdHasher}>
     */
    public function hasherProvider(): array
    {
        // This data provider returns instances of the BcryptHasher, ArgonHasher, and Argon2IdHasher classes, which will be used in the test methods to verify the functionality of each hasher implementation.
        return [
            [new BcryptHasher()],
            [new ArgonHasher()],
            [new Argon2IdHasher()],
        ];
    }

    /**
     * Test that an empty hashed value returns false.
     *
     * @var  BcryptHasher|ArgonHasher|Argon2IdHasher  $hasher
     * @dataProvider hasherProvider
     */
    public function testEmptyHashedValueReturnsFalse(BcryptHasher|ArgonHasher|Argon2IdHasher $hasher): void
    {
        // This test ensures that the check method returns false when the hashed value is empty, confirming that the hasher correctly identifies an empty hashed value as invalid.
        $this->assertFalse(
            condition: $hasher->check(value: 'password', hashedValue: ''),
            message: 'Expected check to return false when hashed value is empty.'
        );
    }

    /**
     * Test that a null hashed value returns false.
     *
     * @var  BcryptHasher|ArgonHasher|Argon2IdHasher  $hasher
     *
     * @dataProvider hasherProvider
     * @return void
     */
    public function testNullHashedValueReturnsFalse(BcryptHasher|ArgonHasher|Argon2IdHasher $hasher): void
    {
        // This test ensures that the check method returns false when the hashed value is null, confirming that the hasher correctly identifies a null hashed value as invalid.
        $this->assertFalse(
            condition: $hasher->check(value: 'password', hashedValue: null),
            message: 'Expected check to return false when hashed value is null.'
        );
    }

    /**
     * Test that bcrypt throws an exception when the value is too long.
     *
     * @return void
     */
    public function testBcryptValueTooLong(): void
    {
        $this->expectException(exception: \InvalidArgumentException::class);

        // Bcrypt has a maximum input length of 72 bytes.
        // This test ensures that an exception is thrown when this limit is exceeded.
        (new BcryptHasher(options: ['limit' => 72]))->make(value: str_repeat(string: 'a', times: 73));
    }

    /**
     * Test basic bcrypt hashing and checking.
     *
     * @return void
     */
    public function testBasicBcryptHashing(): void
    {
        $hasher = new BcryptHasher();
        $hashedPassword = $hasher->make(value: 'password');

        // Bcrypt is a widely used password hashing algorithm that provides a good balance between security and performance. It is designed to be slow and computationally expensive, making it resistant to brute-force attacks. This test ensures that the basic functionality of hashing and verifying passwords with bcrypt works as expected.
        $this->assertNotSame(
            expected: 'password',
            actual: $hashedPassword,
            message: 'Expected the hashed password to be different from the original password.'
        );

        // The check method should return true for a valid password and hashed value, confirming that the hashing and verification process is working correctly.
        $this->assertTrue(
            condition: $hasher->check(value: 'password', hashedValue: $hashedPassword),
            message: 'Expected check to return true for a valid password and hashed value.'
        );

        // The needsRehash method should return false for a valid hashed password, indicating that the current hash is still considered secure based on the configured options.
        $this->assertFalse(
            condition: $hasher->needsRehash(hashedValue: $hashedPassword),
            message: 'Expected needsRehash to return false for a valid hashed password.'
        );

        // The needsRehash method should return true when the options differ from the original hash, indicating that the hash should be rehashed with the new options for improved security.
        $this->assertTrue(
            condition: $hasher->needsRehash(hashedValue: $hashedPassword, options: ['rounds' => 1]),
            message: 'Expected needsRehash to return true when the options differ from the original hash.'
        );

        // The algorithm name should be "bcrypt", confirming that the correct hashing algorithm is being used for the hashed password.
        $this->assertSame(
            expected: 'bcrypt',
            actual: password_get_info(hash: $hashedPassword)['algoName'],
            message: 'Expected the algorithm name to be "bcrypt".'
        );

        // Assert that the cost option is at least 12 rounds, which is a common recommendation for bcrypt to provide a good level of security against brute-force attacks while maintaining reasonable performance.
        $this->assertGreaterThanOrEqual(
            expected: 12,
            actual: password_get_info(hash: $hashedPassword)['options']['cost'],
            message: 'Expected the cost option to be at least 12.'
        );

        // The isHashed method should return true for a valid hashed password, confirming that the hash manager correctly identifies the value as a hashed password.
        $this->assertTrue(
            condition: $this->hashManager->isHashed(value: $hashedPassword),
            message: 'Expected isHashed to return true for a valid hashed password.'
        );

        // Assert that the hashed password is not the same as the original password, confirming that the hashing process is producing a different value for the hashed password.
        $this->assertNotSame(
            expected: 'password',
            actual: $hashedPassword,
            message: 'Expected the hashed password to be different from the original password.'
        );

        // Assert that the hashed password is not empty, confirming that the hashing process is producing a non-empty value for the hashed password.
        $this->assertNotEmpty(
            actual: $hashedPassword,
            message: 'Expected the hashed password to be non-empty.'
        );

        // Assert that the hashed password is a string, confirming that the hashing process is producing a string value for the hashed password.
        $this->assertIsString(
            actual: $hashedPassword,
            message: 'Expected the hashed password to be a string.'
        );
    }

    /**
     * Test basic Argon2i hashing and checking.
     *
     * @return void
     */
    public function testBasicArgon2iHashing(): void
    {
        $hasher = new ArgonHasher;
        $hashedPassword = $hasher->make(value: 'password');

        // Argon2i is designed to be resistant to GPU-based attacks and side-channel attacks, making it a strong choice for password hashing.
        // This test ensures that the basic functionality of hashing and verifying passwords with Argon2i
        $this->assertNotSame(
            expected: 'password',
            actual: $hashedPassword,
            message: 'Expected the hashed password to be different from the original password.'
        );

        // The check method should return true for a valid password and hashed value, confirming that the hashing and verification process is working correctly.
        $this->assertTrue(
            condition: $hasher->check(value: 'password', hashedValue: $hashedPassword),
            message: 'Expected check to return true for a valid password and hashed value.'
        );

        // The needsRehash method should return false for a valid hashed password, indicating that the current hash is still considered secure based on the configured options.
        $this->assertFalse(
            condition: $hasher->needsRehash(hashedValue: $hashedPassword),
            message: 'Expected needsRehash to return false for a valid hashed password.'
        );

        // The needsRehash method should return true when the options differ from the original hash, indicating that the hash should be rehashed with the new options for improved security.
        $this->assertTrue(
            condition: $hasher->needsRehash(hashedValue: $hashedPassword, options: ['threads' => 1]),
            message: 'Expected needsRehash to return true when the options differ from the original hash.'
        );

        // The algorithm name should be "argon2i", confirming that the correct hashing algorithm is being used for the hashed password.
        $this->assertSame(
            expected: 'argon2i',
            actual: password_get_info(hash: $hashedPassword)['algoName'],
            message: 'Expected the algorithm name to be "argon2i".'
        );

        // Assert that the memory cost is at least 65536 KB (64 MB).
        $this->assertGreaterThanOrEqual(
            expected: 65536,
            actual: password_get_info(hash: $hashedPassword)['options']['memory_cost'],
            message: 'Expected the memory cost option to be at least 65536 KB (64 MB).'
        );

        // Assert that the time cost is at least 4 iterations.
        $this->assertGreaterThanOrEqual(
            expected: 4,
            actual: password_get_info(hash: $hashedPassword)['options']['time_cost'],
            message: 'Expected the time cost option to be at least 4 iterations.'
        );

        // Assert that the threads option is at least 1.
        $this->assertGreaterThanOrEqual(
            expected: 1,
            actual: password_get_info(hash: $hashedPassword)['options']['threads'],
            message: 'Expected the threads option to be at least 1.'
        );

        // The isHashed method should return true for a valid hashed password, confirming that the hash manager correctly identifies the value as a hashed password.
        $this->assertTrue(
            condition: $this->hashManager->isHashed(value: $hashedPassword),
            message: 'Expected isHashed to return true for a valid hashed password.'
        );

        // Assert that the hashed password is not the same as the original password, confirming that the hashing process is producing a different value for the hashed password.
        $this->assertNotSame(
            expected: 'password',
            actual: $hashedPassword,
            message: 'Expected the hashed password to be different from the original password.'
        );

        // Assert that the hashed password is not empty, confirming that the hashing process is producing a non-empty value for the hashed password.
        $this->assertNotEmpty(
            actual: $hashedPassword,
            message: 'Expected the hashed password to be non-empty.'
        );

        // Assert that the hashed password is a string, confirming that the hashing process is producing a string value for the hashed password.
        $this->assertIsString(
            actual: $hashedPassword,
            message: 'Expected the hashed password to be a string.'
        );
    }

    /**
     * Test basic Argon2id hashing and checking.
     *
     * @return void
     */
    public function testBasicArgon2idHashing(): void
    {
        $hasher = new Argon2IdHasher;
        $hashedPassword = $hasher->make('password');

        // Argon2id is designed to be resistant to GPU-based attacks and side-channel attacks, making it a strong choice for password hashing.
        // This test ensures that the basic functionality of hashing and verifying passwords with Argon2id works as expected.
        $this->assertNotSame(
            expected: 'password',
            actual: $hashedPassword,
            message: 'Expected the hashed password to be different from the original password.'
        );

        // The check method should return true for a valid password and hashed value, confirming that the hashing and verification process is working correctly.
        $this->assertTrue(
            condition: $hasher->check(value: 'password', hashedValue: $hashedPassword),
            message: 'Expected check to return true for a valid password and hashed value.'
        );

        // The needsRehash method should return false for a valid hashed password, indicating that the current hash is still considered secure based on the configured options.
        $this->assertFalse(
            condition: $hasher->needsRehash(hashedValue: $hashedPassword),
            message: 'Expected needsRehash to return false for a valid hashed password.'
        );

        // The needsRehash method should return true when the options differ from the original hash, indicating that the hash should be rehashed with the new options for improved security.
        $this->assertTrue(
            $hasher->needsRehash(
                hashedValue: $hashedPassword,
                options: ['threads' => 1]
            ),
            message: 'Expected needsRehash to return true when the options differ from the original hash.'
        );

        // The algorithm name should be "argon2id", confirming that the correct hashing algorithm is being used for the hashed password.
        $this->assertSame(
            expected: 'argon2id',
            actual: password_get_info(hash: $hashedPassword)['algoName'],
            message: 'Expected the algorithm name to be "argon2id".'
        );

        // The isHashed method should return true for a valid hashed password, confirming that the hash manager correctly identifies the value as a hashed password.
        $this->assertTrue(
            condition: $this->hashManager->isHashed(value: $hashedPassword),
            message: 'Expected isHashed to return true for a valid hashed password.'
        );

        // Assert that the memory cost is at least 65536 KB (64 MB).
        $this->assertGreaterThanOrEqual(
            expected: 65536,
            actual: password_get_info(hash: $hashedPassword)['options']['memory_cost'],
            message: 'Expected the memory cost option to be at least 65536 KB (64 MB).'
        );

        // Assert that the time cost is at least 4 iterations.
        $this->assertGreaterThanOrEqual(
            expected: 4,
            actual: password_get_info(hash: $hashedPassword)['options']['time_cost'],
            message: 'Expected the time cost option to be at least 4 iterations.'
        );

        // Assert that the threads option is at least 1.
        $this->assertGreaterThanOrEqual(
            expected: 1,
            actual: password_get_info(hash: $hashedPassword)['options']['threads'],
            message: 'Expected the threads option to be at least 1.'
        );

        // The isHashed method should return true for a valid hashed password, confirming that the hash manager correctly identifies the value as a hashed password.
        $this->assertTrue(
            condition: $this->hashManager->isHashed(value: $hashedPassword),
            message: 'Expected isHashed to return true for a valid hashed password.'
        );

        // Assert that the hashed password is not the same as the original password, confirming that the hashing process is producing a different value for the hashed password.
        $this->assertNotSame(
            expected: 'password',
            actual: $hashedPassword,
            message: 'Expected the hashed password to be different from the original password.'
        );

        // Assert that the hashed password is not empty, confirming that the hashing process is producing a non-empty value for the hashed password.
        $this->assertNotEmpty(
            actual: $hashedPassword,
            message: 'Expected the hashed password to be non-empty.'
        );

        // Assert that the hashed password is a string, confirming that the hashing process is producing a string value for the hashed password.
        $this->assertIsString(
            actual: $hashedPassword,
            message: 'Expected the hashed password to be a string.'
        );
    }

    /**
     * Test that verifying a hash with the wrong algorithm throws an exception.
     *
     * @return void
     */
    #[Depends('testBasicBcryptHashing')]
    public function testBasicBcryptVerification(): void
    {
        $this->expectException(exception: RuntimeException::class);

        // This test ensures that an exception is thrown when attempting to verify a hash with the wrong algorithm, confirming that the algorithm verification feature is working as intended.
        (new BcryptHasher(options: ['verify' => true]))
            ->check(
                value: 'password',

                // The hashed value is generated using the ArgonHasher, which should trigger an exception when the BcryptHasher attempts to verify it, confirming that the algorithm verification is functioning correctly.
                hashedValue: (new ArgonHasher(options: ['verify' => true]))->make(value: 'password')
            );
    }

    /**
     * Test that verifying a hash with the wrong algorithm throws an exception.
     *
     * @return void
     */
    #[Depends('testBasicArgon2iHashing')]
    public function testBasicArgon2iVerification(): void
    {
        $this->expectException(RuntimeException::class);

        // This test ensures that an exception is thrown when attempting to verify a hash with the wrong algorithm, confirming that the algorithm verification feature is working as intended.
        (new ArgonHasher(options: ['verify' => true]))
            ->check(
                value: 'password',

                // The hashed value is generated using the BcryptHasher, which should trigger an exception when the ArgonHasher attempts to verify it, confirming that the algorithm verification is functioning correctly.
                hashedValue: (new BcryptHasher(options: ['verify' => true]))->make(value: 'password')
            );
    }

    /**
     * Test that verifying a hash with the wrong algorithm throws an exception.
     *
     * @return void
     */
    #[Depends('testBasicArgon2idHashing')]
    public function testBasicArgon2idVerification(): void
    {
        $this->expectException(exception: RuntimeException::class);

        // This test ensures that an exception is thrown when attempting to verify a hash with the wrong algorithm, confirming that the algorithm verification feature is working as intended.
        (new Argon2IdHasher(options: ['verify' => true]))
            ->check(
                value: 'password',

                // The hashed value is generated using the BcryptHasher, which should trigger an exception when the Argon2IdHasher attempts to verify it, confirming that the algorithm verification is functioning correctly.
                hashedValue: (new BcryptHasher(options: ['verify' => true]))->make(value: 'password')
            );
    }

    /**
     * Test that a non-hashed value returns false.
     *
     * @return void
     */
    public function testIsHashedWithNonHashedValue(): void
    {
        // The isHashed method should return false for a non-hashed value, confirming that the hash manager correctly identifies the value as not being a hashed password.
        $this->assertFalse(
            condition: $this->hashManager->isHashed(value: 'foo'),
            message: 'Expected isHashed to return false for a non-hashed value.'
        );
    }

    /**
     * Test that a hashed value returns true.
     *
     * @return void
     */
    public function testBasicBcryptNotSupported(): void
    {
        $this->expectException(exception: RuntimeException::class);

        // This test ensures that an exception is thrown when attempting to hash a password with bcrypt when the value exceeds the maximum length, confirming that the input length validation is working as intended.
        (new BcryptHasher(options: ['rounds' => 0]))->make(value: 'password');
    }

    /**
     * Test that a hashed value returns true.
     *
     * @return void
     */
    public function testBasicArgon2iNotSupported(): void
    {
        $this->expectException(exception: RuntimeException::class);

        // This test ensures that an exception is thrown when attempting to hash a password with Argon2i when the time cost is set to an invalid value, confirming that the input validation for hashing options is working as intended.
        (new ArgonHasher(options: ['time' => 0]))->make(value: 'password');
    }

    /**
     * Test that a hashed value returns true.
     *
     * @return void
     */
    public function testBasicArgon2idNotSupported(): void
    {
        $this->expectException(exception: RuntimeException::class);

        // This test ensures that an exception is thrown when attempting to hash a password with Argon2id when the time cost is set to an invalid value, confirming that the input validation for hashing options is working as intended.
        (new Argon2IdHasher(options: ['time' => 0]))->make(value: 'password');
    }

    /**
     * Test that the hash manager selects the correct driver based on the default driver configuration.\
     *
     * @return void
     */
    public function testHashManagerDriverSelection(): void
    {
        foreach (['bcrypt', 'argon2i', 'argon2id'] as $driver) {
            $this->hashManager->setDefaultDriver($driver);

            $selectedDriver = $this->hashManager->driver();

            $expectedClass = match ($driver) {
                'bcrypt' => BcryptHasher::class,
                'argon2i' => ArgonHasher::class,
                'argon2id' => Argon2IdHasher::class,
                default => throw new RuntimeException(message: "Unsupported driver: {$driver}"),
            };

            $this->assertInstanceOf($expectedClass, $selectedDriver);
        }
    }
}
