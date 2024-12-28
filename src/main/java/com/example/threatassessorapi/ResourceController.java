package com.example.threatassessorapi;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

@RestController
@RequestMapping(path = "/resources")
public class ResourceController {
    @GetMapping(
            path="/",
            produces = "application/json")
    private static ArrayList<Resource> findAllResources() throws SQLException {
        var resources = new ArrayList<Resource>();
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            ResultSet rs = statement.executeQuery("select * from resource");
            while (rs.next()) {
                var resource = new Resource(
                        rs.getString("resource_type"),
                        rs.getDate("created_at"),
                        rs.getInt("organization_id"));
                resources.add(resource);
            }
        }catch (SQLException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return resources;
    }

    @GetMapping(
            path="/risk",
            produces = "application/json")
    private static Integer getRiskScore() throws SQLException {
        Integer riskScore = 0;
        try (Connection connection = ResourceDB.connect();
             Statement statement = connection.createStatement()) {
            ResultSet rs = statement.executeQuery("SELECT AVG(risk_score) as risk_score FROM vulnerabilities");
            while (rs.next()) {
                riskScore = rs.getInt("risk_score");
            }
        } catch (ClassNotFoundException ex) {
            throw new RuntimeException(ex);
        }
        return riskScore;
    }
}

