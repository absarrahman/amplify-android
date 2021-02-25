package com.amplifyframework.auth

import android.util.Base64
import android.util.Log
import com.amplifyframework.auth.AuthCodeDeliveryDetails.DeliveryMedium.EMAIL
import com.amplifyframework.auth.options.AuthSignInOptions
import com.amplifyframework.auth.result.AuthSignInResult
import com.amplifyframework.auth.result.step.AuthNextSignInStep
import com.amplifyframework.auth.result.step.AuthSignInStep.DONE
import com.amplifyframework.core.Consumer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType.USER_SRP_AUTH
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse
import software.amazon.awssdk.services.cognitoidentityprovider.model.RespondToAuthChallengeRequest
import java.math.BigInteger
import java.text.SimpleDateFormat
import java.util.TimeZone
import java.util.Locale
import java.util.Date
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal class SignInOperation(
    private val cognito: CognitoIdentityProviderClient,
    private val credentialStorage: CredentialStorage,
    private val clientId: String,
    private val clientSecret: String,
    private val poolId: String,
    private val username: String,
    private val password: String,
    private val options: AuthSignInOptions,
    private val onSuccess: Consumer<AuthSignInResult>,
    private val onError: Consumer<AuthException>
) {
    private val helper = AuthenticationHelper(poolId)

    internal fun start() {
        GlobalScope.launch(Dispatchers.IO) {
            try {
                onSuccess.accept(callCognito())
            } catch (error: Throwable) {
                onError.accept(AuthException("Sign in failed.", error, "Try again."))
            }
        }
    }

    private fun callCognito(): AuthSignInResult {
        @Suppress("UsePropertyAccessSyntax") // getA() is NOT "a"!!!!!!
        val request = InitiateAuthRequest.builder()
            .clientId(clientId)
            .authFlow(USER_SRP_AUTH)
            .authParameters(
                mapOf(
                    "USERNAME" to username,
                    "SRP_A" to helper.getA().toString(16),
                    "SECRET_HASH" to SecretHash.of(username, clientId, clientSecret)
                )
            )
            .build()
        val response = cognito.initiateAuth(request)
        Log.w("InitiateAuth", response.toString())

        if (!response.hasChallengeParameters()) {
            storeCredentials(response.authenticationResult())
            val details = AuthCodeDeliveryDetails("TODO: what is this field, actually?", EMAIL)
            val nextStep = AuthNextSignInStep(DONE, emptyMap(), details)
            return AuthSignInResult(true, nextStep)
        }

        when (response.challengeName()) {
            ChallengeNameType.PASSWORD_VERIFIER -> {
                verifyPassword(password, response)
                val details = AuthCodeDeliveryDetails("what is this", EMAIL)
                val nextStep = AuthNextSignInStep(DONE, emptyMap(), details)
                return AuthSignInResult(true, nextStep)
            }
            else -> {
                throw AuthException("Unknown challenge = ${response.challengeName()}", "Implement it!")
            }
        }
    }

    private fun verifyPassword(password: String, initAuthResponse: InitiateAuthResponse) {
        Log.i("SignIn", "verifying password from $initAuthResponse")

        val challengeParameters = initAuthResponse.challengeParameters()!!
        val salt = BigInteger(challengeParameters["SALT"]!!, 16)
        val secretBlock = challengeParameters["SECRET_BLOCK"]!!
        val userIdForSrp = challengeParameters["USER_ID_FOR_SRP"]!!
        val username = challengeParameters["USERNAME"]!!
        val srpB = BigInteger(challengeParameters["SRP_B"]!!, 16)
        val timestamp = computeTimestamp()

        val key = helper.getPasswordAuthenticationKey(userIdForSrp, password, srpB, salt)
        val claimSignature = claimSignature(userIdForSrp, key, timestamp, secretBlock)

        val request = RespondToAuthChallengeRequest.builder()
            .challengeName(initAuthResponse.challengeNameAsString())
            .clientId(clientId)
            .challengeResponses(
                mapOf(
                    "SECRET_HASH" to SecretHash.of(username, clientId, clientSecret),
                    "PASSWORD_CLAIM_SIGNATURE" to claimSignature,
                    "PASSWORD_CLAIM_SECRET_BLOCK" to secretBlock,
                    "TIMESTAMP" to timestamp,
                    "USERNAME" to username
                )
            )
            .session(initAuthResponse.session())
            .build()
        val responseToAuthChallenge = cognito.respondToAuthChallenge(request)
        val authResult = responseToAuthChallenge.authenticationResult()
        storeCredentials(authResult)
    }

    // calculateSignature(hkdf, userPoolId, ChallengeParameters.USER_ID_FOR_SRP, ChallengeParameters.SECRET_BLOCK, dateNow)
    private fun claimSignature(
        userIdForSrp: String,
        key: ByteArray,
        timestamp: String,
        secretBlock: String
    ): String {
        val algorithm = "HmacSHA256"
        val mac = Mac.getInstance(algorithm)
        val keySpec = SecretKeySpec(key, algorithm)
        mac.init(keySpec)
        mac.update(poolId.split("_")[1].toByteArray())
        mac.update(userIdForSrp.toByteArray())
        mac.update(Base64.decode(secretBlock, Base64.NO_WRAP))

        val hmac = mac.doFinal(timestamp.toByteArray())
        return Base64.encodeToString(hmac, Base64.NO_WRAP)
    }

    private fun computeTimestamp(): String {
        val simpleDateFormat = SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US)
        simpleDateFormat.timeZone = TimeZone.getTimeZone("UTC")
        return simpleDateFormat.format(Date())
    }

    private fun storeCredentials(authResult: AuthenticationResultType) {
        Log.i("SignIn", "handling auth result = $authResult")
        credentialStorage.accessToken(authResult.accessToken())
        credentialStorage.idToken(authResult.idToken())
        credentialStorage.refreshToken(authResult.refreshToken())
        credentialStorage.expiresIn(authResult.expiresIn())
        credentialStorage.tokenType(authResult.tokenType())
    }
}