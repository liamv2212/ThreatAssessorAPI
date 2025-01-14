package com.example.threatassessorapi;
import com.google.gson.Gson;
import org.apache.coyote.BadRequestException;
import org.junit.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;

import static com.example.threatassessorapi.DBSeeder.resetTables;

public class UserControllerTest {
    @Test
    public void testGetUsers() throws IOException, URISyntaxException, InterruptedException {
        ArrayList<User> users = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/users/"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();
        httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String userString : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            User user = gson.fromJson(userString, User.class);
            users.add(user);
        }
        for (User user1 : users) {
            System.out.println(user1.toString());
        }
    }

    @Test
    public void testCreateUser() throws IOException, URISyntaxException, InterruptedException {
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
        System.out.println(postResponse.body());
    }
}