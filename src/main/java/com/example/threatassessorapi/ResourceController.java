package com.example.threatassessorapi;

import org.apache.coyote.BadRequestException;
import org.springframework.web.bind.annotation.*;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

import static com.example.threatassessorapi.SQLHelpers.*;

@RestController
@RequestMapping(path = "/resources")
public class ResourceController {
    @GetMapping(
            path="/",
            produces = "application/json")
    private static ArrayList<Resource> findAllResources(@RequestParam("org_id") int orgId,
                                                        @RequestParam(value = "OS", required = false) String OS,
                                                        @RequestParam(value = "resource_type", required = false) String resource_type) throws SQLException, BadRequestException {
        var resources = new ArrayList<Resource>();
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            ResultSet rs = statement.executeQuery("select * from resource where organization_id = " + orgId + getResourceTypeFilter(resource_type) + getOSFilter(OS));
            while (rs.next()) {
                var resource = new Resource(
                        rs.getInt("resource_id"),
                        rs.getString("resource_name"),
                        rs.getDate("created_at"),
                        rs.getInt("organization_id"));
                resources.add(resource);
            }
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return resources;
    }

    @GetMapping(
            path="/vulnerabilities",
            produces = "application/json")
    private static ArrayList<ResourceVulnerability> findAllResourceVulnerabilities(@RequestParam("org_id") int orgId,
                                                                                   @RequestParam(value = "start_date", required = false) Long startDate,
                                                                                   @RequestParam(value = "end_date", required = false) Long endDate,
                                                                                   @RequestParam(value = "OS", required = false) String OS,
                                                                                   @RequestParam(value = "resource_type", required = false) String resource_type
                                                                                   ) throws SQLException, BadRequestException {
        var resourceVulnerabilities = new ArrayList<ResourceVulnerability>();
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            String query = "select resource_id, resource_name, vulnerability_id, vulnerability_name, partition_date, organization_id" +
                    " from resource inner join vulnerabilities using (resource_id, organization_id)" +
                    " where organization_id = " + orgId + getDateFilter(startDate, endDate) + getResourceTypeFilter(resource_type) + getOSFilter(OS) + " group by resource_id, vulnerability_id ";
            ResultSet rs = statement.executeQuery(query);
            while (rs.next()) {
                var resourceVulnerability = new ResourceVulnerability(
                        rs.getInt("resource_id"),
                        rs.getString("resource_name"),
                        rs.getInt("vulnerability_id"),
                        rs.getString("vulnerability_name"),
                        rs.getDate("partition_date"),
                        rs.getInt("organization_id")
                );
                resourceVulnerabilities.add(resourceVulnerability);
            }
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return resourceVulnerabilities;
    }

    @GetMapping(
            path="/{id}/vulnCount",
            produces = "application/json")
    private static VulnCount countVulnsForResource(@RequestParam("org_id") int orgId,
                                                   @RequestParam(value = "start_date", required = false) Long startDate,
                                                   @RequestParam(value = "end_date", required = false) Long endDate,
                                                   @PathVariable("id") int id) throws SQLException, BadRequestException {
        VulnCount vulnCount = null;
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            String query = "WITH countTable as (select resource_id, COUNT(vulnerability_id) vulnCount from vulnerabilities " +
                    "where resource_id = " + id + " " +
                    "and organization_id = " + orgId + getDateFilter(startDate, endDate)
                    + " group by resource_id)" +
                    "select resource_id, resource_name, vulnCount" +
                    " from resource inner join countTable using (resource_id)" +
                    "group by resource_id, resource_name, vulnCount ";
            ResultSet rs = statement.executeQuery(query);
            while (rs.next()) {
                vulnCount = new VulnCount(
                        rs.getInt("resource_id"),
                        rs.getString("resource_name"),
                        rs.getInt("vulnCount")
                );
            }
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return vulnCount;
    }

    @GetMapping(
            path="/vulnCount",
            produces = "application/json")
    private static ArrayList<VulnCount> countVulnsForAllResources(@RequestParam("org_id") int orgId,
                                                                  @RequestParam(value = "start_date", required = false) Long startDate,
                                                                  @RequestParam(value = "end_date", required = false) Long endDate,
                                                                  @RequestParam(value = "OS", required = false) String OS,
                                                                  @RequestParam(value = "resource_type", required = false) String resource_type
                                                       ) throws SQLException, BadRequestException {
        VulnCount vulnCount = null;
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            String query = "WITH countTable as (select resource_id, COUNT(vulnerability_id) vulnCount " +
                    "from vulnerabilities where organization_id = " + orgId + getDateFilter(startDate, endDate) +
                    " group by resource_id)" +
                    "select resource_id, resource_name, vulnCount" +
                    " from resource inner join countTable using (resource_id) WHERE organization_id = " + orgId + getOSFilter(OS) + getResourceTypeFilter(resource_type) +
                    " group by resource_id, resource_name, vulnCount ";
            ResultSet rs = statement.executeQuery(query);
            while (rs.next()) {
                vulnCount = new VulnCount(
                        rs.getInt("resource_id"),
                        rs.getString("resource_name"),
                        rs.getInt("vulnCount")
                );
                vulnCounts.add(vulnCount);
            }
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return vulnCounts;
    }

    @GetMapping(
            path="/count",
            produces = "application/json")
    private static int countAllResources(@RequestParam("org_id") int orgId,
                                         @RequestParam(value = "OS", required = false) String OS,
                                         @RequestParam(value = "resource_type", required = false) String resource_type
    ) throws SQLException, BadRequestException {
        int count = 0;
        try(Connection connection = ResourceDB.connect();
            Statement statement = connection.createStatement()) {
            String query = "select count(DISTINCT resource_id) count" +
                    " from resource WHERE organization_id = " + orgId + getOSFilter(OS) + getResourceTypeFilter(resource_type);
            ResultSet rs = statement.executeQuery(query);
            while (rs.next()) {
                count = rs.getInt("count");
            }
        }catch (Exception e) {
            System.err.println(e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
        return count;
    }
}

