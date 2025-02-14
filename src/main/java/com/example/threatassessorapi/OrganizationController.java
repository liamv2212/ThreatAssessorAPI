package com.example.threatassessorapi;

import org.apache.coyote.BadRequestException;
import org.springframework.web.bind.annotation.*;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;

    @RestController
    @CrossOrigin
    @RequestMapping(path = "/organization")
    public class OrganizationController {

        @GetMapping("/{id}")
        public ArrayList<Organization> getAllOrganizations(@PathVariable("id") int id) throws BadRequestException {
            ArrayList<Organization> users = new ArrayList<>();
            Organization organization = null;
            try(Connection connection = ResourceDB.connect();
                Statement statement = connection.createStatement()) {
                ResultSet rs = statement.executeQuery("select * from organizations where organization_id = " + id);
                while (rs.next()) {
                    organization = new Organization(
                            rs.getString("organization_name"),
                            rs.getInt("organization_id")
                    );
                    users.add(organization);
                }
            }catch (Exception e) {
                System.err.println(e.getMessage());
                throw new BadRequestException(e.getMessage());
            }
            return users;
        }
}
