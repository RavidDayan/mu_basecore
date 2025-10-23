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

UNIT_TEST_STATUS
EFIAPI
TestVerifyMlDsaPreReq (
  UNIT_TEST_CONTEXT  Context
  )
{
  UNIT_TEST_STATUS  Status;

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaPreReq: Entering\n"));

  mMlDsa87 = MlDsaNew (CRYPTO_NID_ML_DSA_87);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaPreReq: mMlDsa87 new object: 0x%x\n", mMlDsa87));
  if (mMlDsa87 == NULL) {
    DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaPreReq: mMlDsa87==NULL 0x%x\n", mMlDsa87));
    Status = UNIT_TEST_ERROR_TEST_FAILED;
    DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaPreReq: Exiting with status 0x%x\n", Status));
    return Status;
  }
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaPreReq: mMlDsa87 passed\n"));
  Status = UNIT_TEST_PASSED;
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaPreReq: Exiting with status 0x%x\n", Status));
  return Status;
}

VOID
EFIAPI
TestVerifyMlDsaCleanUp (
  UNIT_TEST_CONTEXT  Context
  )
{
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaCleanUp: Entering\n"));

  if (mMlDsa87 != NULL) {
    MlDsaFree (mMlDsa87);
    mMlDsa87 = NULL;
  }

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaCleanUp: Exiting\n"));
}

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

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaGenerateKey: Entering\n"));

  //
  // Test ML-DSA-87 key generation
  //
  PublicKeySize  = 0;
  PrivateKeySize = 0;

  // Get required buffer sizes
  Status = MlDsaGenerateKey (mMlDsa87, NULL, &PublicKeySize, NULL, &PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaGenerateKey: Required sizes - PublicKeySize: %u, PrivateKeySize: %u\n", PublicKeySize, PrivateKeySize));
  UT_ASSERT_FALSE (Status);
  UT_ASSERT_EQUAL (PublicKeySize, ML_DSA_87_PUBLIC_KEY_SIZE);
  UT_ASSERT_EQUAL (PrivateKeySize, ML_DSA_87_PRIVATE_KEY_SIZE);

  // Allocate buffers
  PublicKey = AllocatePool (PublicKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaGenerateKey: PublicKey allocated at 0x%x\n", PublicKey));
  if (PublicKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PublicKey");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  PrivateKey = AllocatePool (PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaGenerateKey: PrivateKey allocated at 0x%x\n", PrivateKey));
  if (PrivateKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PrivateKey");
    FreePool (PublicKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  // Generate key pair
  Status = MlDsaGenerateKey (mMlDsa87, PublicKey, &PublicKeySize, PrivateKey, &PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaGenerateKey: Keys generated - Status: %d, PublicKeySize: %u, PrivateKeySize: %u\n", Status, PublicKeySize, PrivateKeySize));
  UT_ASSERT_TRUE (Status);
  UT_ASSERT_EQUAL (PublicKeySize, ML_DSA_87_PUBLIC_KEY_SIZE);
  UT_ASSERT_EQUAL (PrivateKeySize, ML_DSA_87_PRIVATE_KEY_SIZE);

  FreePool (PublicKey);
  FreePool (PrivateKey);

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaGenerateKey: Exiting with status 0x%x\n", UNIT_TEST_PASSED));
  return UNIT_TEST_PASSED;
}

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

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPublicKey: Entering\n"));

  //
  // First generate a key pair
  //
  PublicKeySize  = ML_DSA_87_PUBLIC_KEY_SIZE;
  PrivateKeySize = ML_DSA_87_PRIVATE_KEY_SIZE;
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPublicKey: Initial sizes - PublicKeySize: %u, PrivateKeySize: %u\n", PublicKeySize, PrivateKeySize));

  PublicKey = AllocatePool (PublicKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPublicKey: PublicKey allocated at 0x%x\n", PublicKey));
  if (PublicKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PublicKey");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  PrivateKey = AllocatePool (PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPublicKey: PrivateKey allocated at 0x%x\n", PrivateKey));
  if (PrivateKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PrivateKey");
    FreePool (PublicKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  Status = MlDsaGenerateKey (mMlDsa87, PublicKey, &PublicKeySize, PrivateKey, &PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPublicKey: Keys generated - Status: %d\n", Status));
  UT_ASSERT_TRUE (Status);

  //
  // Test setting public key
  //
  Status = MlDsaSetPublicKey (mMlDsa87, PublicKey, PublicKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPublicKey: SetPublicKey - Status: %d, mMlDsa87: 0x%x, PublicKeySize: %u\n", Status, mMlDsa87, PublicKeySize));
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

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPublicKey: Exiting with status 0x%x\n", UNIT_TEST_PASSED));
  return UNIT_TEST_PASSED;
}

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

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPrivateKey: Entering\n"));

  //
  // First generate a key pair
  //
  PublicKeySize  = ML_DSA_87_PUBLIC_KEY_SIZE;
  PrivateKeySize = ML_DSA_87_PRIVATE_KEY_SIZE;
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPrivateKey: Initial sizes - PublicKeySize: %u, PrivateKeySize: %u\n", PublicKeySize, PrivateKeySize));

  PublicKey = AllocatePool (PublicKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPrivateKey: PublicKey allocated at 0x%x\n", PublicKey));
  if (PublicKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PublicKey");
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  PrivateKey = AllocatePool (PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPrivateKey: PrivateKey allocated at 0x%x\n", PrivateKey));
  if (PrivateKey == NULL) {
    UT_LOG_ERROR ("Failed to allocate memory for PrivateKey");
    FreePool (PublicKey);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  Status = MlDsaGenerateKey (mMlDsa87, PublicKey, &PublicKeySize, PrivateKey, &PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPrivateKey: Keys generated - Status: %d\n", Status));
  UT_ASSERT_TRUE (Status);

  //
  // Test setting private key
  //
  Status = MlDsaSetPrivateKey (mMlDsa87, PrivateKey, PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPrivateKey: SetPrivateKey - Status: %d, mMlDsa87: 0x%x, PrivateKeySize: %u\n", Status, mMlDsa87, PrivateKeySize));
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

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSetPrivateKey: Exiting with status 0x%x\n", UNIT_TEST_PASSED));
  return UNIT_TEST_PASSED;
}

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

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: Entering\n"));

  //
  // First generate a key pair
  //
  PublicKeySize  = ML_DSA_87_PUBLIC_KEY_SIZE;
  PrivateKeySize = ML_DSA_87_PRIVATE_KEY_SIZE;
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: Initial sizes - PublicKeySize: %u, PrivateKeySize: %u\n", PublicKeySize, PrivateKeySize));

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
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: Keys generated - Status: %d\n", Status));
  UT_ASSERT_TRUE (Status);

  //
  // Set private key for signing
  //
  Status = MlDsaSetPrivateKey (mMlDsa87, PrivateKey, PrivateKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: PrivateKey set - Status: %d\n", Status));
  UT_ASSERT_TRUE (Status);

  //
  // Test ML-DSA signature generation
  //
  SigSize = 0;
  Status  = MlDsaSign (mMlDsa87, (CONST UINT8 *)MlDsaSignData, AsciiStrLen (MlDsaSignData), NULL, &SigSize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: Signature size required: %u\n", SigSize));
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
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: Signed - Status: %d, SigSize: %u, Signature: 0x%x\n", Status, SigSize, Signature));
  UT_ASSERT_TRUE (Status);
  UT_ASSERT_EQUAL (SigSize, ML_DSA_87_SIGNATURE_SIZE);

  //
  // Set public key for verification
  //
  Status = MlDsaSetPublicKey (mMlDsa87, PublicKey, PublicKeySize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: PublicKey set for verify - Status: %d\n", Status));
  UT_ASSERT_TRUE (Status);

  //
  // Test ML-DSA signature verification
  //
  Status = MlDsaVerify (mMlDsa87, (CONST UINT8 *)MlDsaSignData, AsciiStrLen (MlDsaSignData), Signature, SigSize);
  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: Verification - Status: %d\n", Status));
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

  DEBUG ((DEBUG_ERROR, "TestVerifyMlDsaSignVerify: Exiting with status 0x%x\n", UNIT_TEST_PASSED));
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
