package com.example.threatassessorapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;

import java.sql.*;
import java.util.ArrayList;

@SpringBootApplication
@RestController
public class ThreatAssessorApiApplication {

	public static void main(String[] args) throws SQLException {
		SpringApplication.run(ThreatAssessorApiApplication.class, args);
	}
}
