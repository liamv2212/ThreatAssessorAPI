package com.example.threatassessorapi;
import com.google.gson.Gson;
import org.junit.Test;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UserControllerTest {
    @Test
    @Order(1)
    public void testGetUsers() throws IOException, URISyntaxException, InterruptedException {
        ArrayList<User> users = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String userString : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            User user = gson.fromJson(userString, User.class);
            users.add(user);
        }
        assertEquals(getResponse.statusCode(), 200);
    }

    @Test
    @Order(2)
    public void testGetUserByName() throws IOException, URISyntaxException, InterruptedException {
        User user = null;
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/liamv"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String userString : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            user = gson.fromJson(userString, User.class);
        }
        assert user != null;
        assertEquals(user.getUserName(), "liamv");
        assertEquals(200, getResponse.statusCode());

    }

    @Test
    @Order(2)
    public void testGetUserOrganization() throws IOException, URISyntaxException, InterruptedException {
        Integer organization = null;
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/liamv/organization"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String userString : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            organization = gson.fromJson(userString, Integer.class);
        }
        assert organization != null;
        assertEquals(organization, 1);
        assertEquals(200, getResponse.statusCode());

    }

    @Test
    @Order(2)
    public void testGetUserOrganization_InvalidName() throws IOException, URISyntaxException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/liams/organization"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());

        assertEquals(400, getResponse.statusCode());

    }

    @Test
    @Order(3)
    public void testCreateUser_1() throws IOException, URISyntaxException, InterruptedException {
        ArrayList<User> users = new ArrayList<>();
        User user = new User("username", "password", 1);
        Gson gson = new Gson();
        String json = gson.toJson(user);
        System.out.println(json);
        HttpRequest postRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> postResponse = httpClient.send(postRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, postResponse.statusCode());
    }

    @Test
    @Order(4)
    public void testCreateUser_2() throws IOException, URISyntaxException, InterruptedException {
        ArrayList<User> users = new ArrayList<>();
        User user = new User("username", "password", 1);
        Gson gson = new Gson();
        String json = gson.toJson(user);
        HttpRequest postRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> postResponse = httpClient.send(postRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(postResponse.body());
        assertEquals(400, postResponse.statusCode());
    }

    @Test
    @Order(5)
    public void testDeleteUser() throws IOException, URISyntaxException, InterruptedException {
        ArrayList<User> users = new ArrayList<>();
        HttpRequest postRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/?name=username&password=password&orgId=1"))
                .header("Content-Type", "application/json")
                .DELETE()
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> postResponse = httpClient.send(postRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(postResponse.body(), "User username Deleted for organization: 1");
        assertEquals(200, postResponse.statusCode());
    }

    @Test
    @Order(6)
    public void testDeleteUserNotFound() throws IOException, URISyntaxException, InterruptedException {
        ArrayList<User> users = new ArrayList<>();
        User user = new User("username", "password", 1);
        Gson gson = new Gson();;
        String json = gson.toJson(user);
        HttpRequest postRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/"))
                .header("Content-Type", "application/json")
                .DELETE()
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> postResponse = httpClient.send(postRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, postResponse.statusCode());
    }
}