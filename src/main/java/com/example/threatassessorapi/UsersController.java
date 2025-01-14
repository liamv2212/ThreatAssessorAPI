package com.example.threatassessorapi;

import org.apache.coyote.BadRequestException;
import org.springframework.web.bind.annotation.*;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;

@RestController
@RequestMapping(path = "/users")
public class UsersController {
    @GetMapping("/")
    public ArrayList<User> getAllUsers() throws BadRequestException {
        ArrayList<User> users = new ArrayList<>();
        User user = null;
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            ResultSet rs = statement.executeQuery("select * from users");
            while (rs.next()) {
                user = new User(
                     rs.getString("user_name"),
                     rs.getString("password"),
                     rs.getInt("organization_id")
                );
                users.add(user);
            }
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return users;
    }

    @GetMapping("/{name}")
    public ArrayList<User> getUserByName(@PathVariable("name") String name) throws BadRequestException {
        ArrayList<User> users = new ArrayList<>();
        User user = null;
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            ResultSet rs = statement.executeQuery("select * from users where user_name = '" + name + "'");
            if(rs.next()){
                user = new User(
                        rs.getString("user_name"),
                        rs.getString("password"),
                        rs.getInt("organization_id")
                );
                users.add(user);
            }
            else throw new BadRequestException("User not found");
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return users;
    }

    @GetMapping("/{name}/organization")
    public Integer getUserOrg(@PathVariable("name") String name) throws BadRequestException {
        int organization_id;
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            ResultSet rs = statement.executeQuery("select organization_id from users where user_name = '" + name + "'");
            if (rs.next()) {
                organization_id = rs.getInt("organization_id");
            }
            else throw new BadRequestException("No user found");
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return organization_id;
    }

    @PostMapping("/")
    public String createUser(@RequestBody(required = true) User user) throws BadRequestException {
        System.out.println();
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            ResultSet rs = statement.executeQuery("Insert Into users values ('" + user.getUserName() + "', '" + user.getPassword() + "', '" + user.getOrgID() + "')");
        }catch (Exception e) {
            if (e.getMessage().equals("No results were returned by the query.")) {
                return "User Created for organization: " + user.getOrgID();
            } else {
                System.out.println(e.getMessage());
                throw new BadRequestException(e.getMessage());
            }
        }
        return null;
    }

@DeleteMapping("/")
public String DeleteUser(@RequestBody(required = true) User user) throws BadRequestException {
    try(Connection connection = ResourceDB.connect();
        Statement statement = connection.createStatement()) {
        ResultSet rs = statement.executeQuery("select * from users where user_name = '" + user.getUserName() + "' and password = '" + user.getPassword() + "' and organization_id = '" + user.getOrgID() + "'");
        if (rs.next()) {
            statement.executeQuery("Delete from users where user_name = '" + user.getUserName() + "' and password = '" + user.getPassword() + "' and organization_id = '" + user.getOrgID() + "'");
        }
        else{
            throw new BadRequestException("No user found");
        }
    }catch (Exception e) {
        if (e.getMessage().equals("No results were returned by the query.")) {
            return "User " + user.getUserName() + " Deleted for organization: " + user.getOrgID();
        } else {
            System.out.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
    }
    return null;
}
}
