import { createHash } from "crypto";
import {
  CreateAuthChallengeTriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from "aws-lambda";
import {
  DynamoDBClient,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import {
  logger,
  UserFacingError,
  handleConditionalCheckFailedException,
} from "./common.js";

let config = {
  /** Should SMS OTP Code sign-in be enabled? If set to false, clients cannot sign-in with SMS OTP codes (an error is shown instead when they request an SMS OTP code) */
  smsOtpEnabled: !!process.env.SMS_OTP_ENABLED,
  /** The length of the SMS OTP code */
  otpLength: Number(process.env.OTP_LENGTH || 6),
  /** Number of seconds an SMS OTP Code should be valid */
  secondsUntilExpiry: Number(process.env.SECONDS_UNTIL_EXPIRY || 60 * 5), // Shorter validity for SMS
  /** Number of seconds that must lapse between unused SMS OTP Codes (to prevent misuse) */
  minimumSecondsBetween: Number(process.env.MIN_SECONDS_BETWEEN || 30 * 1),
  /** Amazon SNS origination number to use for sending SMS messages */
  originationNumber: process.env.ORIGINATION_NUMBER || undefined,
  /** Amazon SNS sender ID to use for sending SMS messages */
  senderId: process.env.SENDER_ID || undefined,
  /** The Amazon SNS region, override e.g. to use a different region */
  snsRegion: process.env.SNS_REGION || process.env.AWS_REGION,
  /** The name of the DynamoDB table where (hashes of) SMS OTP Codes will be stored */
  dynamodbSecretsTableName: process.env.DYNAMODB_OTP_SECRETS_TABLE,
  /** Function that will send the actual SMS OTP Code messages. Override this to e.g. use another SMS provider instead of Amazon SNS */
  smsSender: sendSmsWithOtpCode,
  /** A salt to use for storing hashes of SMS OTP codes in the DynamoDB table */
  salt: process.env.STACK_ID,
  /** Function to create the content of the SMS OTP Code messages, override to e.g. use a custom template */
  contentCreator: createSmsContent,
  /** Error message that will be shown to the client, if the client requests an SMS OTP Code but isn't allowed to yet */
  notNowMsg:
    "We can't send you an SMS OTP code right now, please try again in a minute",
  /** Function to mask the phone nr that will be visible in the public challenge parameters */
  phoneNrMasker: maskPhoneNumber,
};

function requireConfig<K extends keyof typeof config>(
  k: K
): NonNullable<(typeof config)[K]> {
  // eslint-disable-next-line security/detect-object-injection
  const value = config[k];
  if (value === undefined) throw new Error(`Missing configuration for: ${k}`);
  return value;
}

export function configure(update?: Partial<typeof config>) {
  const oldSnsRegion = config.snsRegion;
  config = { ...config, ...update };
  if (update && update.snsRegion !== oldSnsRegion) {
    sns = new SNSClient({ region: config.snsRegion });
  }
  return config;
}

const ddbDocClient = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
  marshallOptions: {
    removeUndefinedValues: true,
  },
});
let sns = new SNSClient({ region: config.snsRegion });

export async function addChallengeToEvent(
  event: CreateAuthChallengeTriggerEvent
): Promise<void> {
  if (!config.smsOtpEnabled)
    throw new UserFacingError("Sign-in with SMS OTP Code not supported");
  event.response.challengeMetadata = "SMS_OTP_CODE";
  const alreadyHaveSmsOtpCode =
    event.request.clientMetadata?.alreadyHaveSmsOtpCode;
  if (alreadyHaveSmsOtpCode === "yes") {
    // The client already has a sign-in code, we don't need to send a new one
    logger.info("Client will use already obtained SMS OTP code");
    return;
  }
  logger.info("Client needs SMS OTP code");

  // let phoneNumber =
  //   event.request.userAttributes.phone_number_verified === "true"
  //     ? event.request.userAttributes.phone_number
  //     : undefined;
  let phoneNumber = event.request.userAttributes.phone_number;  // No matter if verified or not

  // The event.request.userNotFound is only present in the Lambda trigger if "Prevent user existence errors" is checked
  // in the Cognito app client. If it is *not* checked, the client receives the error, which potentially allows for
  // user enumeration. Additional guardrails are advisable.
  if (event.request.userNotFound) {
    logger.info("User not found, cannot send SMS OTP");
    // Optionally generate a dummy phone number for timing consistency if needed, but don't send SMS
    // phoneNumber = `+${[...Buffer.from(event.userName)].join("").slice(0, 10)}`; // Example dummy
    // Cannot proceed without a real phone number if user exists
  }

  if (!phoneNumber) {
    throw new UserFacingError(
      "Cannot send SMS OTP: User has no phone number"
    );
  }

  const otpParams = JSON.parse(event.request.clientMetadata?.otpParams ?? "{}");
  // Send challenge with new secret login code
  await createAndSendSmsOtpCode(event, phoneNumber, otpParams);

  // Send masked phone number back to client
  event.response.publicChallengeParameters = {
    phoneNumber: config.phoneNrMasker(phoneNumber),
  };

  event.response.privateChallengeParameters = {
    phoneNumber: phoneNumber, // Keep original phone number for verification step
  };
}

async function createSmsContent({
  otpCode, otpParams
}: {
  otpCode: string;
  otpParams: any;
}) {
  return `Your verification code is: ${otpCode}`;
}

async function sendSmsWithOtpCode({
  phoneNumber,
  message,
}: {
  phoneNumber: string;
  message: string;
}) {
  const attributes: PublishCommand["input"]["MessageAttributes"] = {
    "AWS.SNS.SMS.SMSType": {
      StringValue: "Transactional",
      DataType: "String",
    },
  };
  if (config.senderId) {
    attributes["AWS.SNS.SMS.SenderID"] = {
      DataType: "String",
      StringValue: config.senderId,
    };
  }
  if (config.originationNumber) {
    attributes["AWS.MM.SMS.OriginationNumber"] = {
      DataType: "String",
      StringValue: config.originationNumber,
    };
  }

  await sns
    .send(
      new PublishCommand({
        PhoneNumber: phoneNumber,
        Message: message,
        MessageAttributes: attributes,
      })
    )
    .catch((err) => {
      logger.error("Failed to send SMS:", err);
      // Handle specific SNS errors if needed
      throw new UserFacingError(
        "Failed to send SMS OTP code. Please try again later."
      );
    });
}

async function createAndSendSmsOtpCode(
  event: CreateAuthChallengeTriggerEvent,
  phoneNumber: string,
  otpParams: any,
): Promise<void> {
  logger.debug("Creating new SMS OTP code ...");
  const exp = Math.floor(Date.now() / 1000 + config.secondsUntilExpiry);
  const iat = Math.floor(Date.now() / 1000);
  // Check whether a hard-coded OTP code is provided
  const hardcodedOtpCode = otpParams.fixedOtpCode;

  // Generate a random numeric OTP code if no hard-coded OTP code is provided
  const otpCode = hardcodedOtpCode ? hardcodedOtpCode : Array(config.otpLength)
    .fill(0)
    .map(() => Math.floor(Math.random() * 10))
    .join('');

  // Context for hashing can include more details if needed for security
  const messageContext = Buffer.from(
    JSON.stringify({
      // userPoolId: event.userPoolId, // Optional: include if needed for hash uniqueness
      // clientId: event.callerContext.clientId, // Optional: include if needed for hash uniqueness
      otpCode: otpCode,
    })
  );

  logger.debug("Storing SMS OTP code hash in DynamoDB ...");
  const salt = requireConfig("salt");
  await ddbDocClient
    .send(
      new PutCommand({
        TableName: requireConfig("dynamodbSecretsTableName"),
        Item: {
          // Use userName as the primary key identifier in the OTP table
          userNameHash: createHash("sha256")
            .update(salt)
            .end(event.userName)
            .digest(),
          optCodeHash: createHash("sha256")
            .update(salt)
            .end(messageContext) // Hash the context containing the OTP
            .digest(),
          iat,
          exp,
        },
        // Throttle: fail if we've already sent an OTP less than minimumSecondsBetween seconds ago:
        ConditionExpression: "attribute_not_exists(#iat) or #iat < :iat",
        ExpressionAttributeNames: {
          "#iat": "iat",
        },
        ExpressionAttributeValues: {
          ":iat": Math.floor(Date.now() / 1000) - config.minimumSecondsBetween,
        },
      })
    )
    .catch(handleConditionalCheckFailedException(config.notNowMsg));

  logger.debug("Sending SMS OTP code ...");
  // Do not send SMS if user was not found (already checked in addChallengeToEvent)
  if (event.request.userNotFound) {
    logger.info("User not found, SMS OTP not sent.");
    return;
  }

  await config.smsSender({
    phoneNumber: phoneNumber,
    message: await config.contentCreator.call(undefined, {
      otpCode: otpCode,
      otpParams: otpParams,
    }),
  });
  logger.debug("SMS OTP code sent!");
}

export async function addChallengeVerificationResultToEvent(
  event: VerifyAuthChallengeResponseTriggerEvent
) {
  logger.info("Verifying SMS OTP Code Challenge Response ...");
  // Toggle userNotFound error with "Prevent user existence errors" in the Cognito app client.
  if (event.request.userNotFound) {
    // This case should ideally not be reached if verification is only triggered for existing users,
    // but handle defensively. Verification will fail as no OTP was stored/sent.
    logger.info("User not found during verification attempt.");
  }
  if (!config.smsOtpEnabled)
    throw new UserFacingError("Sign-in with SMS OTP Code not supported");

  // Avoid verification if this is the initial PROVIDE_AUTH_PARAMETERS challenge
  // or if client indicates they didn't have an SMS code (e.g., chose a different method)
  if (
    event.request.privateChallengeParameters.challenge ===
      "PROVIDE_AUTH_PARAMETERS" &&
    event.request.clientMetadata?.alreadyHaveSmsOtpCode !== "yes"
  ) {
    logger.debug("Skipping SMS OTP verification for initial auth or client without code.");
    // Let Cognito decide the next step; don't set answerCorrect.
    return;
  }

  const phoneNumber = event.request.userAttributes.phone_number;
  if (!phoneNumber) {
     logger.error("Phone number missing in private challenge parameters during verification");
     event.response.answerCorrect = false;
     return;
  }

  event.response.answerCorrect = await verifySmsOtpCode(
    event.request.challengeAnswer, // This is the OTP code entered by the user
    event.userName,
    phoneNumber,
    {
      userPoolId: event.userPoolId,
      clientId: event.callerContext.clientId,
    }
  );
}

async function verifySmsOtpCode(
  otpCode: string,
  userName: string,
  phoneNumber: string, // Added phoneNumber for potential future use in verification logic/logging
  context: { userPoolId: string; clientId: string }
) {
  logger.debug(
    `Verifying SMS OTP code "${otpCode}" for user:`,
    userName,
    `Phone: ${phoneNumber}` // Log phone number for context
  );
  // Read and update item from DynamoDB. If the item has `uat` (used at)
  // attribute, no update is performed and no item is returned.
  let dbItem: Record<string, unknown> | undefined = undefined;
  try {
    // Hash the userName and OTP code context to check against the stored hash
    const salt = requireConfig("salt");
    const userNameHash = createHash("sha256")
      .update(salt)
      .end(userName)
      .digest();
    const optCodeHash = createHash("sha256")
      .update(salt)
      .end(
        Buffer.from(
          JSON.stringify({
            // Ensure this context matches the one used during storage
            // userPoolId: context.userPoolId, // Include if used in storage
            // clientId: context.clientId, // Include if used in storage
            otpCode: otpCode,
          })
        )
      )
      .digest();
    const uat = Math.floor(Date.now() / 1000);

    ({ Attributes: dbItem } = await ddbDocClient.send(
      new UpdateCommand({
        TableName: requireConfig("dynamodbSecretsTableName"),
        Key: {
          // Key is based on userNameHash
          userNameHash,
        },
        ReturnValues: "ALL_OLD",
        // Mark the OTP as used by setting 'uat'
        UpdateExpression: "SET #uat = :uat",
        // Condition: OTP must exist, match the hash, and not be used already
        ConditionExpression:
          "attribute_exists(#userNameHash) AND attribute_exists(#optCodeHash) AND #optCodeHash = :optCodeHash AND attribute_not_exists(#uat)",
        ExpressionAttributeNames: {
          "#userNameHash": "userNameHash",
          "#optCodeHash": "optCodeHash",
          "#uat": "uat",
        },
        ExpressionAttributeValues: {
          ":optCodeHash": optCodeHash,
          ":uat": uat,
        },
      })
    ));
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      // This means the ConditionExpression failed:
      // - userNameHash didn't exist (user never requested OTP or incorrect user?)
      // - optCodeHash didn't exist or didn't match (wrong OTP code)
      // - uat already exists (OTP code already used)
      logger.error(
        "Attempt to use invalid, incorrect, or already used SMS OTP code."
      );
      return false; // Verification fails
    }
    // Rethrow unexpected errors
    logger.error("Error during DynamoDB update for OTP verification:", err);
    throw new UserFacingError("Error verifying SMS OTP code. Please try again.");
  }

  // If dbItem is undefined after the UpdateCommand, it means the item was not updated
  // (likely due to the ConditionExpression failing, handled above, but double-check)
  if (!dbItem) {
    logger.error("SMS OTP code record not found or condition failed during update.");
    return false;
  }

  assertIsSmsOtpCodeRecord(dbItem); // Validate the structure of the retrieved record

  // Check if the OTP code has expired
  if (dbItem.exp < Date.now() / 1000) {
    logger.error("SMS OTP code expired");
    // Optionally, you might want to clean up expired records here or periodically
    return false;
  }

  logger.debug(`SMS OTP code is valid`);
  return true; // Verification successful
}

// Type assertion for the DynamoDB record
function assertIsSmsOtpCodeRecord(msg: unknown): asserts msg is {
  userNameHash: Uint8Array; // Changed from string to Uint8Array to match digest output
  optCodeHash: Uint8Array; // Changed from string to Uint8Array
  exp: number;
  iat: number;
  uat?: number;
} {
  if (
    !msg ||
    typeof msg !== "object" ||
    !("userNameHash" in msg) ||
    !(msg.userNameHash instanceof Uint8Array) || // Check for Uint8Array
    !("optCodeHash" in msg) ||
    !(msg.optCodeHash instanceof Uint8Array) || // Check for Uint8Array
    !("exp" in msg) ||
    typeof msg.exp !== "number" ||
    !("iat" in msg) ||
    typeof msg.iat !== "number" ||
    ("uat" in msg && typeof msg.uat !== "number")
  ) {
    throw new Error("Invalid SMS OTP code record from DynamoDB");
  }
}

// Utility function to mask phone number
function maskPhoneNumber(phoneNumber: string): string {
  // Ensure input is a string and potentially clean it
  const digitsOnly = String(phoneNumber).replace(/\D/g, '');
  const length = digitsOnly.length;
  if (length < 7) {
    // If too short to mask meaningfully, return partially masked or original
    return `***${digitsOnly.slice(-2)}`;
  }
  // Show last 4 digits, mask the rest
  const show = 4;
  const masked = '*'.repeat(length - show) + digitsOnly.slice(-show);
  // Add '+' back if original had it
  return (phoneNumber.startsWith('+') ? '+' : '') + masked;
} 