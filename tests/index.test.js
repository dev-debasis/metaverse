// const { default: axios } = require("axios");
import axios from "axios";

const BACKEND_URL = "http://localhost:3000";

describe("Authentication", () => {
  test("User is able to sign up only once", async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";

    const response = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    const anotherResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    expect(response.statusCode).toBe(200);
    expect(anotherResponse.statusCode).toBe(400);
    expect(anotherResponse.message).toBe("user already exists");
  });

  test("signup response fails if the fields are empty", async () => {
    const response = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username: "",
      password: "12345678",
      type: "admin",
    });

    const anotherResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password: "",
      type: "admin",
    });

    expect(response.statusCode).toBe(400);
    expect(response.message).toBe("username cannot be empty");
    expect(anotherResponse.statusCode).toBe(400);
    expect(anotherResponse.message).toBe("password cannot be empty");
  });

  test("User is able to sign in after giving correct credentials", async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";

    const signUpResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    const signInResponse = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username,
      password,
    });

    expect(signUpResponse.statusCode).toBe(200);
    expect(signInResponse.statusCode).toBe(200);
  });

  test("User is not able to signin if the credentials are wrong", async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";

    const signUpResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    const signInResponse = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username: "randomUser" + Math.round(Math.random() * 10000),
      password,
    });

    const anotherSignInResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        username,
        password: "00000000",
      }
    );

    expect(signUpResponse.statusCode).toBe(200);
    expect(signInResponse.statusCode).toBe(403);
    expect(signInResponse.message).toBe("Invalid username");
    expect(anotherSignInResponse.statusCode).toBe(403);
    expect(anotherSignInResponse.message).toBe("Invalid password");
  });

  test("Account locks after 5 failed log-in attempts", async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";

    const signUpResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    for (let i = 0; i < 5; i++) {
      await axios.post(`${BACKEND_URL}/api/v1/signin`, {
        username: "randomUser" + Math.round(Math.random() * 10000),
        password: "0000",
      });
    }

    const signInResponse = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username,
      password,
    });

    expect(signInResponse.statusCode).toBe(403);
    expect(signInResponse.data.message).toBe(
      "Account locked as you did 5 failed attempts"
    );
  });

  test("password changing workflow", async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const oldPassword = "12345678";
    const newPassword = "87654321";

    await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password: oldPassword,
      type: "admin",
    });

    const passwordChangeResponse = await axios.post(
      `${BACKEND_URL}/api/v1/change-password`,
      {
        username,
        password: oldPassword,
        newPassword,
      }
    );

    const signInWithNewPasswordResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        username,
        password: newPassword,
      }
    );

    const signInWithOldPasswordResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        username,
        password: oldPassword,
      }
    );

    expect(passwordChangeResponse.statusCode).toBe(200);
    expect(passwordChangeResponse.message).toBe(
      "Password changed successfully"
    );
    expect(signInWithNewPasswordResponse.statusCode).toBe(200);
    expect(signInWithOldPasswordResponse.statusCode).toBe(403);
  });

  test("Role based authentication control", async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const userPassword = "12345678";

    const adminusername = "admin" + Math.round(Math.random() * 1000);
    const adminPassword = "87654321";

    await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      userPassword,
      type: "user",
    });

    await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      adminusername,
      adminPassword,
      type: "admin",
    });

    const userSignInResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        username,
        userPassword,
      }
    );

    const adminSignInResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        adminusername,
        adminPassword,
      }
    );

    const userToken = userSignInResponse.data.token;
    const adminToken = adminSignInResponse.data.token;

    const userResponse = await axios.get(
      `${BACKEND_URL}/api/v1/admin-protected`,
      {
        headers: {
          Authorization: `Bearer ${userToken}`,
        },
      }
    );

    const adminResponse = await axios.get(
      `${BACKEND_URL}/api/v1/admin-protected`,
      {
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
      }
    );

    expect(userResponse.statusCode).toBe(403);
    expect(userResponse.message).toBe(
      "You are not authorized to access this route"
    );
    expect(adminResponse.statusCode).toBe(200);
  });

  test("Session log out validation", async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";

    const signUpResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    const signInResponse = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username,
      password,
    });

    const token = signInResponse.data.token;

    const signOutResponse = await axios.post(`${BACKEND_URL}/api/v1/signout`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const protectedRouteResponse = await axios.get(
      `${BACKEND_URL}/api/v1/protected`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    expect(signOutResponse.statusCode).toBe(200);
    expect(signOutResponse.message).toBe("Logged out successfully");
    expect(protectedRouteResponse.statusCode).toBe(403);
  });
});


describe("User metadata endpoints", () => {
  let token = "";
  let avatarId = "";

  beforeAll(async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";
    await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    const response = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username,
      password,
    });

    token = response.data.token;

    const createAvatarResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/avatar`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQm3RFDZM21teuCMFYx_AROjt-AzUwDBROFww&s",
        name: "Debasis",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    avatarId = createAvatarResponse.data.avatarId;
  });

  test("User can't update their metadata if the avatar id is wrong", async () => {
    const avatarId = "73837383838344";
    const response = await axios.post(`${BACKEND_URL}/api/v1/user/metadata`, {
      avatarId,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.message).toBe("Invalid avatar id");
  });

  test("User can update their metadata if the avatar id is correct", async () => {
    const response = await axios.post(`${BACKEND_URL}/api/v1/user/metadata`, {
      avatarId,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.message).toBe("Metadata updated successfully");
  });

  test("User can't update their metadata if user is not authorized / the auth header is not present", async () => {
    const response = await axios.post(`${BACKEND_URL}/api/v1/user/metadata`, {
      avatarId,
    });

    expect(response.statusCode).toBe(403);
    expect(response.message).toBe("Unauthorized Access");
  });
});


describe("Users metadata", () => {
  let avatarId = "";
  let userId = "";
  beforeAll(async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";
    const signInResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    userId = signInResponse.data.userId;

    await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username,
      password,
    });

    const createAvatarResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/avatar`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQm3RFDZM21teuCMFYx_AROjt-AzUwDBROFww&s",
        name: "Debasis",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    avatarId = createAvatarResponse.data.avatarId;
  });

  test("Get back avatar information", async () => {
    const response = await axios.get(
      `${BACKEND_URL}/api/v1/user/metadata/bulk?ids=[avatarId]`
    );

    expect(response.data.avatars.length).toBe(1);
    expect(response.data.avatars[0].userId).toBe(userId);
  });

  test("Get available avatars", async () => {
    const response = await axios.get(`${BACKEND_URL}/api/v1/avatars`);

    expect(response.data.avatars.length).toBeGreaterThan(0);

    const currentAvatar = response.data.avatars.find(
      (avatar) => avatar.id === avatarId
    );

    expect(currentAvatar).toBeDefined();
  });
});


describe("Space information", () => {
  let mapId;
  let element1Id;
  let element2Id;
  let adminToken;
  let adminId;
  let userToken;
  let userId;

  beforeAll(async () => {
    const username = "user" + Math.round(Math.random() * 1000);
    const password = "12345678";

    const signupResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    adminId = signupResponse.data.userId;

    const response = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username,
      password,
    });

    adminToken = response.data.token;

    const userSignupResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signup`,
      {
        username: username + "-user",
        password,
        type: "user",
      }
    );

    userId = userSignupResponse.data.userId;

    const userSigninResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        username: username + "-user",
        password,
      }
    );

    userToken = userSigninResponse.data.token;

    const element1Response = await axios.post(
      `${BACKEND_URL}/api/v1/admin/element`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRCRca3wAR4zjPPTzeIY9rSwbbqB6bB2hVkoTXN4eerXOIkJTG1GpZ9ZqSGYafQPToWy_JTcmV5RHXsAsWQC3tKnMlH_CsibsSZ5oJtbakq&usqp=CAE",
        width: 1,
        height: 1,
        static: true,
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const element2Response = await axios.post(
      `${BACKEND_URL}/api/v1/admin/element`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRCRca3wAR4zjPPTzeIY9rSwbbqB6bB2hVkoTXN4eerXOIkJTG1GpZ9ZqSGYafQPToWy_JTcmV5RHXsAsWQC3tKnMlH_CsibsSZ5oJtbakq&usqp=CAE",
        width: 1,
        height: 1,
        static: true,
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );
    element1Id = element1Response.data.id;
    element2Id = element2Response.data.id;
    console.log(element1Id);
    console.log(element2Id);
    const mapResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/map`,
      {
        thumbnail: "https://thumbnail.com/a.png",
        dimensions: "100x200",
        name: "Test space",
        defaultElements: [
          {
            elementId: element1Id,
            x: 20,
            y: 20,
          },
          {
            elementId: element1Id,
            x: 18,
            y: 20,
          },
          {
            elementId: element2Id,
            x: 19,
            y: 20,
          },
        ],
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );
    console.log("mapResponse.status");
    console.log(mapResponse.data.id);

    mapId = mapResponse.data.id;
  });

  test("User is able to create a space", async () => {
    const response = await axios.post(
      `${BACKEND_URL}/api/v1/space`,
      {
        name: "Test",
        dimensions: "100x200",
        mapId: mapId,
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );
    expect(response.status).toBe(200);
    expect(response.data.spaceId).toBeDefined();
  });

  test("User is able to create a space without mapId (empty space)", async () => {
    const response = await axios.post(
      `${BACKEND_URL}/api/v1/space`,
      {
        name: "Test",
        dimensions: "100x200",
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(response.data.spaceId).toBeDefined();
  });

  test("User is not able to create a space without mapId and dimensions", async () => {
    const response = await axios.post(
      `${BACKEND_URL}/api/v1/space`,
      {
        name: "Test",
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(response.status).toBe(400);
  });

  test("User is not able to delete a space that doesn't exist", async () => {
    const response = await axios.delete(
      `${BACKEND_URL}/api/v1/space/randomIdDoesntExist`,
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(response.status).toBe(400);
  });

  test("User is able to delete a space that does exist", async () => {
    const response = await axios.post(
      `${BACKEND_URL}/api/v1/space`,
      {
        name: "Test",
        dimensions: "100x200",
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    const deleteResponse = await axios.delete(
      `${BACKEND_URL}/api/v1/space/${response.data.spaceId}`,
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(deleteResponse.status).toBe(200);
  });

  test("User should not be able to delete a space created by another user", async () => {
    const response = await axios.post(
      `${BACKEND_URL}/api/v1/space`,
      {
        name: "Test",
        dimensions: "100x200",
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    const deleteResponse = await axios.delete(
      `${BACKEND_URL}/api/v1/space/${response.data.spaceId}`,
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );

    expect(deleteResponse.status).toBe(403);
  });

  test("Admin has no spaces initially", async () => {
    const response = await axios.get(`${BACKEND_URL}/api/v1/space/all`, {
      headers: {
        authorization: `Bearer ${adminToken}`,
      },
    });
    expect(response.data.spaces.length).toBe(0);
  });

  test("Admin has gets once space after", async () => {
    const spaceCreateResponse = await axios.post(
      `${BACKEND_URL}/api/v1/space`,
      {
        name: "Test",
        dimensions: "100x200",
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );
    const response = await axios.get(`${BACKEND_URL}/api/v1/space/all`, {
      headers: {
        authorization: `Bearer ${adminToken}`,
      },
    });
    const filteredSpace = response.data.spaces.find(
      (x) => x.id == spaceCreateResponse.data.spaceId
    );
    expect(response.data.spaces.length).toBe(1);
    expect(filteredSpace).toBeDefined();
  });
});


describe("Arena endpoints", () => {
  let mapId;
  let element1Id;
  let element2Id;
  let adminToken;
  let adminId;
  let userToken;
  let userId;
  let spaceId;

  beforeAll(async () => {
    const username = `debasis-${Math.random()}`;
    const password = "123456";

    const signupResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    adminId = signupResponse.data.userId;

    const response = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username: username,
      password,
    });

    adminToken = response.data.token;

    const userSignupResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signup`,
      {
        username: username + "-user",
        password,
        type: "user",
      }
    );

    userId = userSignupResponse.data.userId;

    const userSigninResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        username: username + "-user",
        password,
      }
    );

    userToken = userSigninResponse.data.token;

    const element1Response = await axios.post(
      `${BACKEND_URL}/api/v1/admin/element`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRCRca3wAR4zjPPTzeIY9rSwbbqB6bB2hVkoTXN4eerXOIkJTG1GpZ9ZqSGYafQPToWy_JTcmV5RHXsAsWQC3tKnMlH_CsibsSZ5oJtbakq&usqp=CAE",
        width: 1,
        height: 1,
        static: true,
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const element2Response = await axios.post(
      `${BACKEND_URL}/api/v1/admin/element`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRCRca3wAR4zjPPTzeIY9rSwbbqB6bB2hVkoTXN4eerXOIkJTG1GpZ9ZqSGYafQPToWy_JTcmV5RHXsAsWQC3tKnMlH_CsibsSZ5oJtbakq&usqp=CAE",
        width: 1,
        height: 1,
        static: true,
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );
    element1Id = element1Response.data.id;
    element2Id = element2Response.data.id;

    const mapResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/map`,
      {
        thumbnail: "https://thumbnail.com/a.png",
        dimensions: "100x200",
        name: "Default space",
        defaultElements: [
          {
            elementId: element1Id,
            x: 20,
            y: 20,
          },
          {
            elementId: element1Id,
            x: 18,
            y: 20,
          },
          {
            elementId: element2Id,
            x: 19,
            y: 20,
          },
        ],
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );
    mapId = mapResponse.data.id;

    const spaceResponse = await axios.post(
      `${BACKEND_URL}/api/v1/space`,
      {
        name: "Test",
        dimensions: "100x200",
        mapId: mapId,
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );
    spaceId = spaceResponse.data.spaceId;
  });

  test("Incorrect spaceId returns a 400", async () => {
    const response = await axios.get(
      `${BACKEND_URL}/api/v1/space/random3737spa3e`,
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );
    expect(response.status).toBe(400);
  });

  test("Correct spaceId returns all the elements", async () => {
    const response = await axios.get(`${BACKEND_URL}/api/v1/space/${spaceId}`, {
      headers: {
        authorization: `Bearer ${userToken}`,
      },
    });
    expect(response.data.dimensions).toBe("100x200");
    expect(response.data.elements.length).toBe(3);
  });

  test("Delete endpoint is able to delete an element", async () => {
    const response = await axios.get(`${BACKEND_URL}/api/v1/space/${spaceId}`, {
      headers: {
        authorization: `Bearer ${userToken}`,
      },
    });
    x;

    let res = await axios.delete(`${BACKEND_URL}/api/v1/space/element`, {
      data: { id: response.data.elements[0].id },
      headers: {
        authorization: `Bearer ${userToken}`,
      },
    });

    const newResponse = await axios.get(
      `${BACKEND_URL}/api/v1/space/${spaceId}`,
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(newResponse.data.elements.length).toBe(2);
  });

  test("Adding an element fails if the element lies outside the dimensions", async () => {
    const newResponse = await axios.post(
      `${BACKEND_URL}/api/v1/space/element`,
      {
        elementId: element1Id,
        spaceId: spaceId,
        x: 600000,
        y: 440000,
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(newResponse.status).toBe(400);
  });

  test("Adding an element works as expected", async () => {
    await axios.post(
      `${BACKEND_URL}/api/v1/space/element`,
      {
        elementId: element1Id,
        spaceId: spaceId,
        x: 50,
        y: 20,
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    const newResponse = await axios.get(
      `${BACKEND_URL}/api/v1/space/${spaceId}`,
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(newResponse.data.elements.length).toBe(3);
  });
});


describe("Admin Endpoints", () => {
  let adminToken;
  let adminId;
  let userToken;
  let userId;

  beforeAll(async () => {
    const username = "debasis" + Math.round(Math.random() * 1000);
    const password = "123456";

    const signupResponse = await axios.post(`${BACKEND_URL}/api/v1/signup`, {
      username,
      password,
      type: "admin",
    });

    adminId = signupResponse.data.userId;

    const response = await axios.post(`${BACKEND_URL}/api/v1/signin`, {
      username: username,
      password,
    });

    adminToken = response.data.token;

    const userSignupResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signup`,
      {
        username: username + "-user",
        password,
        type: "user",
      }
    );

    userId = userSignupResponse.data.userId;

    const userSigninResponse = await axios.post(
      `${BACKEND_URL}/api/v1/signin`,
      {
        username: username + "-user",
        password,
      }
    );

    userToken = userSigninResponse.data.token;
  });

  test("User is not able to hit admin Endpoints", async () => {
    const elementResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/element`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRCRca3wAR4zjPPTzeIY9rSwbbqB6bB2hVkoTXN4eerXOIkJTG1GpZ9ZqSGYafQPToWy_JTcmV5RHXsAsWQC3tKnMlH_CsibsSZ5oJtbakq&usqp=CAE",
        width: 1,
        height: 1,
        static: true,
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    const mapResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/map`,
      {
        thumbnail: "https://thumbnail.com/a.png",
        dimensions: "100x200",
        name: "test space",
        defaultElements: [],
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    const avatarResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/avatar`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQm3RFDZM21teuCMFYx_AROjt-AzUwDBROFww&s",
        name: "Timmy",
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    const updateElementResponse = await axios.put(
      `${BACKEND_URL}/api/v1/admin/element/123`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQm3RFDZM21teuCMFYx_AROjt-AzUwDBROFww&s",
      },
      {
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      }
    );

    expect(elementResponse.status).toBe(403);
    expect(mapResponse.status).toBe(403);
    expect(avatarResponse.status).toBe(403);
    expect(updateElementResponse.status).toBe(403);
  });

  test("Admin is able to hit admin Endpoints", async () => {
    const elementResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/element`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRCRca3wAR4zjPPTzeIY9rSwbbqB6bB2hVkoTXN4eerXOIkJTG1GpZ9ZqSGYafQPToWy_JTcmV5RHXsAsWQC3tKnMlH_CsibsSZ5oJtbakq&usqp=CAE",
        width: 1,
        height: 1,
        static: true,
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const mapResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/map`,
      {
        thumbnail: "https://thumbnail.com/a.png",
        name: "Space",
        dimensions: "100x200",
        defaultElements: [],
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const avatarResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/avatar`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQm3RFDZM21teuCMFYx_AROjt-AzUwDBROFww&s",
        name: "Timmy",
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );
    expect(elementResponse.status).toBe(200);
    expect(mapResponse.status).toBe(200);
    expect(avatarResponse.status).toBe(200);
  });

  test("Admin is able to update the imageUrl for an element", async () => {
    const elementResponse = await axios.post(
      `${BACKEND_URL}/api/v1/admin/element`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/shopping?q=tbn:ANd9GcRCRca3wAR4zjPPTzeIY9rSwbbqB6bB2hVkoTXN4eerXOIkJTG1GpZ9ZqSGYafQPToWy_JTcmV5RHXsAsWQC3tKnMlH_CsibsSZ5oJtbakq&usqp=CAE",
        width: 1,
        height: 1,
        static: true,
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const updateElementResponse = await axios.put(
      `${BACKEND_URL}/api/v1/admin/element/${elementResponse.data.id}`,
      {
        imageUrl:
          "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQm3RFDZM21teuCMFYx_AROjt-AzUwDBROFww&s",
      },
      {
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      }
    );

    expect(updateElementResponse.status).toBe(200);
  });
});