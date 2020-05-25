import AWS from "aws-sdk";
import util from "util";
import jwt from "jsonwebtoken";
import axios from "axios";
import jwkToPem from "jwk-to-pem";

const { promisify } = util;

AWS.config.update({
  accessKeyId: process.env.AWS_ACC_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET,
});

const COGNITO_CLIENT = new AWS.CognitoIdentityServiceProvider({
  apiVersion: "2016-04-19",
  region: "ap-southeast-2",
});

const utilPromiseRegisterUser = promisify(COGNITO_CLIENT.adminCreateUser).bind(
  COGNITO_CLIENT
);

const utilPromiseSetPassword = promisify(
  COGNITO_CLIENT.adminSetUserPassword
).bind(COGNITO_CLIENT);

const utilPromiseInitAuth = util
  .promisify(COGNITO_CLIENT.initiateAuth)
  .bind(COGNITO_CLIENT);

const utilPromiseAdminLogout = promisify(
  COGNITO_CLIENT.adminUserGlobalSignOut
).bind(COGNITO_CLIENT);

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

export const logout = async (event, context) => {
  const data = JSON.parse(event.body);
  //console.log(data);
  const { token } = data;

  let result = await axios.get(
    `https://cognito-idp.${process.env.AWS_REGION_JWK}.amazonaws.com/${process.env.AWS_POOLID}/.well-known/jwks.json`
  );
  const pem = jwkToPem(result.data.keys[1]);
  const decoded = jwt.verify(token, pem, { algorithm: ["RS256"] });
  const userParams = {
    UserPoolId: process.env.AWS_POOLID /* required */,
    Username: decoded.username,
  };
  //console.log(decoded);
  await utilPromiseAdminLogout(userParams);
  return {
    statusCode: 200,
    body: "all good",
  };
};
