package com.example.threatassessorapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;

import java.sql.*;

import static com.example.threatassessorapi.DBSeeder.resetTables;

@SpringBootApplication
@RestController
public class ThreatAssessorApiApplication {

	public static void main(String[] args) throws SQLException {
//		resetTables();
		SpringApplication.run(ThreatAssessorApiApplication.class, args);
	}
}
