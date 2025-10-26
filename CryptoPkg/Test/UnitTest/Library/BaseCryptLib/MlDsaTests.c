/** @file
  Application for ML-DSA (Module-Lattice-Based Digital Signature Algorithm) Validation.

Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestBaseCryptLib.h"

//
// Test data for ML-DSA-87 signature verification
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST CHAR8  MlDsaSignData[] = "OpenSSL ML-DSA Test Message";

VOID  *mMlDsa87;

/**
  Prerequisite function for ML-DSA unit tests.

  This function initializes the ML-DSA-87 context object that will be used
  across all ML-DSA test cases. It creates a new ML-DSA instance with the
  NIST-standardized ML-DSA-87 parameter set, which provides security level 5.
  This prerequisite runs before each individual test case to ensure a clean
  test environment.

  @param[in]  Context  Unit test context (unused).

  @retval  UNIT_TEST_PASSED             ML-DSA context successfully created.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  Failed to create ML-DSA context.

**/
UNIT_TEST_STATUS
EFIAPI
TestVerifyMlDsaPreReq (
  UNIT_TEST_CONTEXT  Context
  )
{
  UNIT_TEST_STATUS  Status;

  mMlDsa87 = MlDsaNew (CRYPTO_NID_ML_DSA_87);
  if (mMlDsa87 == NULL) {
    Status = UNIT_TEST_ERROR_TEST_FAILED;
    return Status;
  }

  Status = UNIT_TEST_PASSED;
  return Status;
}

/**
  Cleanup function for ML-DSA unit tests.

  This function frees the ML-DSA-87 context object after each test case
  completes. It ensures proper memory cleanup and prevents resource leaks
  between test executions. This cleanup runs after each individual test
  case finishes, regardless of test success or failure.

  @param[in]  Context  Unit test context (unused).

**/
VOID
EFIAPI
TestVerifyMlDsaCleanUp (
  UNIT_TEST_CONTEXT  Context
  )
{
  if (mMlDsa87 != NULL) {
    MlDsaFree (mMlDsa87);
    mMlDsa87 = NULL;
  }
}

/**
  Unit test for ML-DSA-87 key pair generation.

  This test validates the ML-DSA key generation functionality by:
  1. Querying required buffer sizes for public and private keys
  2. Verifying the returned sizes match ML-DSA-87 specifications
     (2592 bytes for public key, 4032 bytes for private key)
  3. Allocating appropriate buffers for the keys
  4. Generating a complete ML-DSA-87 key pair
  5. Validating the generated key sizes

  The test ensures that the MlDsaGenerateKey function correctly implements
  the FIPS 204 ML-DSA-87 key generation algorithm and returns properly
  sized cryptographic key material.

  @param[in]  Context  Unit test context (unused).

  @retval  UNIT_TEST_PASSED             All key generation tests passed.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  Memory allocation failed.

**/
UNIT_TEST_STATUS
EFIAPI
TestVerifyMlDsaGenerateKey (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  BOOLEAN  Status;
  UINT8    *PublicKey;
  UINTN    PublicKeySize;
  UINT8    *PrivateKey;
  UINTN    PrivateKeySize;

  //
  // Test ML-DSA-87 key generation
  //
  PublicKeySize  = 0;
  PrivateKeySize = 0;

  // Get required buffer sizes
  Status = MlDsaGenerateKey (mMlDsa87, NULL, &PublicKeySize, NULL, &PrivateKeySize);
  UT_ASSERT_FALSE (Status);
  UT_ASSERT_EQUAL (PublicKeySize, ML_DSA_87_PUBLIC_KEY_SIZE);
  UT_ASSERT_EQUAL (PrivateKeySize, ML_DSA_87_PRIVATE_KEY_SIZE);

  // Allocate buffers
  PublicKey = AllocatePool (PublicKeySize);
  if (PublicKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PublicKey");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  PrivateKey = AllocatePool (PrivateKeySize);
  if (PrivateKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PrivateKey");
    FreePool (PublicKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  // Generate key pair
  Status = MlDsaGenerateKey (mMlDsa87, PublicKey, &PublicKeySize, PrivateKey, &PrivateKeySize);
  UT_ASSERT_TRUE (Status);
  UT_ASSERT_EQUAL (PublicKeySize, ML_DSA_87_PUBLIC_KEY_SIZE);
  UT_ASSERT_EQUAL (PrivateKeySize, ML_DSA_87_PRIVATE_KEY_SIZE);

  FreePool (PublicKey);
  FreePool (PrivateKey);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for ML-DSA-87 public key configuration.

  This test validates the ability to set a public key in an ML-DSA context by:
  1. Generating a valid ML-DSA-87 key pair
  2. Setting the public key into the ML-DSA context using MlDsaSetPublicKey
  3. Verifying the operation succeeds with valid parameters
  4. Testing error handling with NULL context parameter
  5. Testing error handling with NULL public key buffer

  This function is essential for verification operations where only the
  public key is available (e.g., signature verification). The test ensures
  proper parameter validation and successful key loading into the context.

  @param[in]  Context  Unit test context (unused).

  @retval  UNIT_TEST_PASSED             All public key configuration tests passed.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  Memory allocation failed.

**/
UNIT_TEST_STATUS
EFIAPI
TestVerifyMlDsaSetPublicKey (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  BOOLEAN  Status;
  UINT8    *PublicKey;
  UINTN    PublicKeySize;
  UINT8    *PrivateKey;
  UINTN    PrivateKeySize;

  //
  // First generate a key pair
  //
  PublicKeySize  = ML_DSA_87_PUBLIC_KEY_SIZE;
  PrivateKeySize = ML_DSA_87_PRIVATE_KEY_SIZE;

  PublicKey = AllocatePool (PublicKeySize);
  if (PublicKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PublicKey");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  PrivateKey = AllocatePool (PrivateKeySize);
  if (PrivateKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PrivateKey");
    FreePool (PublicKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  Status = MlDsaGenerateKey (mMlDsa87, PublicKey, &PublicKeySize, PrivateKey, &PrivateKeySize);
  UT_ASSERT_TRUE (Status);

  //
  // Test setting public key
  //
  Status = MlDsaSetPublicKey (mMlDsa87, PublicKey, PublicKeySize);
  UT_ASSERT_TRUE (Status);

  //
  // Test invalid parameters
  //
  Status = MlDsaSetPublicKey (NULL, PublicKey, PublicKeySize);
  UT_ASSERT_FALSE (Status);

  Status = MlDsaSetPublicKey (mMlDsa87, NULL, PublicKeySize);
  UT_ASSERT_FALSE (Status);

  FreePool (PublicKey);
  FreePool (PrivateKey);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for ML-DSA-87 private key configuration.

  This test validates the ability to set a private key in an ML-DSA context by:
  1. Generating a valid ML-DSA-87 key pair
  2. Setting the private key into the ML-DSA context using MlDsaSetPrivateKey
  3. Verifying the operation succeeds with valid parameters
  4. Testing error handling with NULL context parameter
  5. Testing error handling with NULL private key buffer

  This function is essential for signing operations where the private key
  must be loaded into the context. The test ensures proper parameter
  validation and secure handling of the private key material.

  @param[in]  Context  Unit test context (unused).

  @retval  UNIT_TEST_PASSED             All private key configuration tests passed.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  Memory allocation failed.

**/
UNIT_TEST_STATUS
EFIAPI
TestVerifyMlDsaSetPrivateKey (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  BOOLEAN  Status;
  UINT8    *PublicKey;
  UINTN    PublicKeySize;
  UINT8    *PrivateKey;
  UINTN    PrivateKeySize;

  //
  // First generate a key pair
  //
  PublicKeySize  = ML_DSA_87_PUBLIC_KEY_SIZE;
  PrivateKeySize = ML_DSA_87_PRIVATE_KEY_SIZE;

  PublicKey = AllocatePool (PublicKeySize);
  if (PublicKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PublicKey");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  PrivateKey = AllocatePool (PrivateKeySize);
  if (PrivateKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PrivateKey");
    FreePool (PublicKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  Status = MlDsaGenerateKey (mMlDsa87, PublicKey, &PublicKeySize, PrivateKey, &PrivateKeySize);
  UT_ASSERT_TRUE (Status);

  //
  // Test setting private key
  //
  Status = MlDsaSetPrivateKey (mMlDsa87, PrivateKey, PrivateKeySize);
  UT_ASSERT_TRUE (Status);

  //
  // Test invalid parameters
  //
  Status = MlDsaSetPrivateKey (NULL, PrivateKey, PrivateKeySize);
  UT_ASSERT_FALSE (Status);

  Status = MlDsaSetPrivateKey (mMlDsa87, NULL, PrivateKeySize);
  UT_ASSERT_FALSE (Status);

  FreePool (PublicKey);
  FreePool (PrivateKey);

  return UNIT_TEST_PASSED;
}

/**
  Unit test for ML-DSA-87 signature generation and verification.

  This test validates the complete ML-DSA signature workflow by:
  1. Generating a fresh ML-DSA-87 key pair
  2. Configuring the context with the private key for signing
  3. Querying the required signature buffer size (4595 bytes for ML-DSA-87)
  4. Generating a digital signature over test message data
  5. Configuring the context with the public key for verification
  6. Verifying the signature is valid for the original message
  7. Testing that verification fails for a different message (negative test)
  8. Testing error handling with NULL context parameters

  This end-to-end test ensures the ML-DSA implementation correctly performs
  the FIPS 204 signature and verification algorithms, providing post-quantum
  secure digital signatures. The test confirms that signatures can only be
  verified with the correct message, maintaining cryptographic integrity.

  @param[in]  Context  Unit test context (unused).

  @retval  UNIT_TEST_PASSED             All signature/verification tests passed.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  Memory allocation failed.

**/
UNIT_TEST_STATUS
EFIAPI
TestVerifyMlDsaSignVerify (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  BOOLEAN  Status;
  UINT8    *PublicKey;
  UINTN    PublicKeySize;
  UINT8    *PrivateKey;
  UINTN    PrivateKeySize;
  UINT8    *Signature;
  UINTN    SigSize;

  //
  // First generate a key pair
  //
  PublicKeySize  = ML_DSA_87_PUBLIC_KEY_SIZE;
  PrivateKeySize = ML_DSA_87_PRIVATE_KEY_SIZE;

  PublicKey = AllocatePool (PublicKeySize);
  if (PublicKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PublicKey");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  PrivateKey = AllocatePool (PrivateKeySize);
  if (PrivateKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PrivateKey");
    FreePool (PublicKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  Status = MlDsaGenerateKey (mMlDsa87, PublicKey, &PublicKeySize, PrivateKey, &PrivateKeySize);
  UT_ASSERT_TRUE (Status);

  //
  // Set private key for signing
  //
  Status = MlDsaSetPrivateKey (mMlDsa87, PrivateKey, PrivateKeySize);
  UT_ASSERT_TRUE (Status);

  //
  // Test ML-DSA signature generation
  //
  SigSize = 0;
  Status  = MlDsaSign (mMlDsa87, (CONST UINT8 *)MlDsaSignData, AsciiStrLen (MlDsaSignData), NULL, &SigSize);
  UT_ASSERT_FALSE (Status);
  UT_ASSERT_EQUAL (SigSize, ML_DSA_87_SIGNATURE_SIZE);

  Signature = AllocatePool (SigSize);
  if (Signature == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for Signature");
    FreePool (PublicKey);
    FreePool (PrivateKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  Status = MlDsaSign (mMlDsa87, (CONST UINT8 *)MlDsaSignData, AsciiStrLen (MlDsaSignData), Signature, &SigSize);
  UT_ASSERT_TRUE (Status);
  UT_ASSERT_EQUAL (SigSize, ML_DSA_87_SIGNATURE_SIZE);

  //
  // Set public key for verification
  //
  Status = MlDsaSetPublicKey (mMlDsa87, PublicKey, PublicKeySize);
  UT_ASSERT_TRUE (Status);

  //
  // Test ML-DSA signature verification
  //
  Status = MlDsaVerify (mMlDsa87, (CONST UINT8 *)MlDsaSignData, AsciiStrLen (MlDsaSignData), Signature, SigSize);
  UT_ASSERT_TRUE (Status);

  //
  // Test verification with wrong message
  //
  Status = MlDsaVerify (mMlDsa87, (CONST UINT8 *)"Wrong Message", AsciiStrLen ("Wrong Message"), Signature, SigSize);
  UT_ASSERT_FALSE (Status);

  //
  // Test invalid parameters
  //
  Status = MlDsaSign (NULL, (CONST UINT8 *)MlDsaSignData, AsciiStrLen (MlDsaSignData), Signature, &SigSize);
  UT_ASSERT_FALSE (Status);

  Status = MlDsaVerify (NULL, (CONST UINT8 *)MlDsaSignData, AsciiStrLen (MlDsaSignData), Signature, SigSize);
  UT_ASSERT_FALSE (Status);

  FreePool (PublicKey);
  FreePool (PrivateKey);
  FreePool (Signature);

  return UNIT_TEST_PASSED;
}

TEST_DESC  mMlDsaTest[] = {
  //
  // -----Description--------------------------------------Class----------------------Function---------------------------------Pre---------------------Post---------Context
  //
  { "TestVerifyMlDsaGenerateKey()",   "CryptoPkg.BaseCryptLib.MlDsa", TestVerifyMlDsaGenerateKey,   TestVerifyMlDsaPreReq, TestVerifyMlDsaCleanUp, NULL },
  { "TestVerifyMlDsaSetPublicKey()",  "CryptoPkg.BaseCryptLib.MlDsa", TestVerifyMlDsaSetPublicKey,  TestVerifyMlDsaPreReq, TestVerifyMlDsaCleanUp, NULL },
  { "TestVerifyMlDsaSetPrivateKey()", "CryptoPkg.BaseCryptLib.MlDsa", TestVerifyMlDsaSetPrivateKey, TestVerifyMlDsaPreReq, TestVerifyMlDsaCleanUp, NULL },
  { "TestVerifyMlDsaSignVerify()",    "CryptoPkg.BaseCryptLib.MlDsa", TestVerifyMlDsaSignVerify,    TestVerifyMlDsaPreReq, TestVerifyMlDsaCleanUp, NULL },
};

UINTN  mMlDsaTestNum = ARRAY_SIZE (mMlDsaTest);
