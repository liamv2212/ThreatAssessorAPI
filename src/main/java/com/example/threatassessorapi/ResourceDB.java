package com.example.threatassessorapi;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class ResourceDB {
    public static Connection connect() throws SQLException, ClassNotFoundException {
        String url = "jdbc:postgresql://localhost:5432/postgres";
        String user = "postgres";
        String password = "**********"; //Removed for Submission
        Class.forName("org.postgresql.Driver");
        return DriverManager.getConnection(url, user, password);
    }
}
