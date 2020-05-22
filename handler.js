import AWS from "aws-sdk";
import util from "util";

AWS.config.update({
  accessKeyId: process.env.AWS_ACC_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET,
});

const COGNITO_CLIENT = new AWS.CognitoIdentityServiceProvider({
  apiVersion: "2016-04-19",
  region: "ap-southeast-2",
});

const utilPromiseRegisterUser = util
  .promisify(COGNITO_CLIENT.adminCreateUser)
  .bind(COGNITO_CLIENT);

const utilPromiseSetPassword = util
  .promisify(COGNITO_CLIENT.adminSetUserPassword)
  .bind(COGNITO_CLIENT);

const utilPromiseInitAuth = util
  .promisify(COGNITO_CLIENT.initiateAuth)
  .bind(COGNITO_CLIENT);

export const register = async (event, ctx) => {
  const data = JSON.parse(event.body);
  const { email, password } = data;
  // let awsUserName = "";
  // console.log(email);
  // console.log(password);
  const createUserParams = {
    UserPoolId: process.env.AWS_POOLID,
    Username: email,
    DesiredDeliveryMediums: ["EMAIL"],
    ForceAliasCreation: false,
    TemporaryPassword: password,
    UserAttributes: [{ Name: "email", Value: email }],
  };
  const passwordParams = {
    Password: password /* required */,
    UserPoolId: process.env.AWS_POOLID /* required */,
    Username: email /* required */,
    Permanent: true,
  };
  await utilPromiseRegisterUser(createUserParams);
  await utilPromiseSetPassword(passwordParams);
  return {
    statusCode: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": true,
    },
    body: "User created",
  };
};
export const login = async (event, ctx) => {
  const data = JSON.parse(event.body);
  const { email, password } = data;
  const userAuthParams = {
    ClientId: process.env.AWS_CLIENT_ID,
    AuthFlow: "USER_PASSWORD_AUTH",
    AnalyticsMetadata: {
      AnalyticsEndpointId: "STRING_VALUE",
    },
    AuthParameters: {
      USERNAME: email,
      PASSWORD: password,
    },
  };
  let response = await utilPromiseInitAuth(userAuthParams);
  const token = response.AuthenticationResult.AccessToken;
  //console.log(response);
  return {
    statusCode: 200,
    body: JSON.stringify({ token }),
  };
};
