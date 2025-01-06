package com.example.threatassessorapi;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Random;
@RestController
@RequestMapping(path = "/db")
public class DBSeeder {
    static Random rand = new Random();
    static int org_id = 1;
    static ArrayList<LocalDate> partition_dates = new ArrayList<>();

    @GetMapping(
            path="/reset",
            produces = "application/json")
    public static void resetTables(){
        dropTables();
        createOrganizationsTable();
        createResourceTable();
        createVulnerabilitiesTable();
        createOrganizations();
        createResources();
        createVulnerabilities();
    }

    private static void createVulnerabilities() {
        String[] alphabet = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};

        for (int i = 0; i < 10; i++) {
            int resourceId = i+1;
            for (int x=0; x<10; x++) {
                partition_dates.clear();
                StringBuilder vulnerability = new StringBuilder();
                int riskScore = rand.nextInt(1000);
                    int nameLength = rand.nextInt(25) + 1;
                    for (int j = 0; j < nameLength; j++) {
                        vulnerability.append(alphabet[rand.nextInt(alphabet.length)]);
                    }
                    for (int k = 0; k< rand.nextInt(10); k++){
                        partition_dates.add(LocalDate.now().minusWeeks(k));
                    }
                    for(int l = 0; l<partition_dates.size(); l++) {
                        try (Connection connection = ResourceDB.connect();
                             Statement statement = connection.createStatement()) {
                            String sqlQuery = "INSERT INTO vulnerabilities(vulnerability_name, resource_id, organization_id, risk_score, first_found, partition_date)\n" +
                                    "VALUES ('" + vulnerability + "'," + resourceId + "," + org_id + "," + riskScore + ", '" + partition_dates.get(partition_dates.size() - 1) + "', '" + partition_dates.get(l) + "');";
                            statement.executeQuery(sqlQuery);
                        } catch (SQLException | ClassNotFoundException e) {
                        }
                    }
            }
        }
    }

    private static void createOrganizations() {
        String[] alphabet = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};

        for (int i = 0; i < 5; i++) {
            StringBuilder organizationName = new StringBuilder();

            try (Connection connection = ResourceDB.connect();
                 Statement statement = connection.createStatement()) {
                int nameLength = rand.nextInt(25) + 1;
                for (int j = 0; j < nameLength; j++) {
                    organizationName.append(alphabet[rand.nextInt(alphabet.length)]);
                }
                String sqlQuery = "INSERT INTO organizations (organization_name)\n" +
                        "VALUES ('" + organizationName + "');";
                statement.executeQuery(sqlQuery);
            } catch (SQLException | ClassNotFoundException e) {
            }
        }
    }

    private static void createResources() {
        String[] alphabet = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};
        String resource_type;
        String OS;
        for (int i = 0; i < 10; i++) {
            StringBuilder resourceType = new StringBuilder();
            try (Connection connection = ResourceDB.connect();
                 Statement statement = connection.createStatement()) {
                int typeLength = rand.nextInt(25) + 1;
                for (int j = 0; j < typeLength; j++) {
                    resourceType.append(alphabet[rand.nextInt(alphabet.length)]);
                }
                if (rand.nextInt(2) == 1){
                    resource_type = "CLOUD";
                }
                else resource_type = "ON-PREM";
                if (rand.nextInt(3) == 1){
                    OS = "WINDOWS";
                } else if (rand.nextInt(3) == 2) {
                    OS = "MAC";
                } else OS = "LINUX";
                String sqlQuery = "INSERT INTO resource (resource_name, created_at, organization_id, operating_system, resource_type)\n" +
                        "VALUES ('" + resourceType + "', '2024/12/27'," + org_id + ", '" + OS + "', '" + resource_type + "')";
                statement.executeQuery(sqlQuery);
            } catch (SQLException | ClassNotFoundException e) {
            }
        }
    }

    private static void createVulnerabilitiesTable() {
        try (Connection connection = ResourceDB.connect();
             Statement statement = connection.createStatement()) {
            statement.executeQuery("create table vulnerabilities\n" +
                    "(\n" +
                    "    vulnerability_id  bigint generated by default as identity\n" +
                    "        constraint vulnerabilities_pk\n" +
                    "            primary key,\n" +
                    "    vulnerability_name text   not null,\n" +
                    "    resource_id       bigint not null\n" +
                    "        constraint vulnerabilities_resource_id_fk\n" +
                    "            references resource,\n" +
                    "    organization_id   bigint not null\n" +
                    "        constraint vulnerabilities_organizations_organization_id_fk\n" +
                    "            references organizations,\n" +
                    "    risk_score        bigint not null,\n" +
                    "    first_found       date   not null,\n" +
                    "    partition_date    date   not null\n" +
                    ");\n" +
                    "\n" +
                    "alter table vulnerabilities\n" +
                    "    owner to postgres;\n" +
                    "\n");
        } catch (SQLException | ClassNotFoundException e) {
        }
    }

    private static void createOrganizationsTable() {
        try (Connection connection = ResourceDB.connect();
             Statement statement = connection.createStatement()) {
            statement.executeQuery("create table organizations\n" +
                    "(\n" +
                    "    organization_name text not null,\n" +
                    "    organization_id   bigint generated by default as identity\n" +
                    "        constraint organizations_pk\n" +
                    "            primary key\n" +
                    ");\n" +
                    "\n" +
                    "comment on column organizations.organization_name is 'Name of an organization';\n" +
                    "\n" +
                    "alter table organizations\n" +
                    "    owner to postgres;");
        } catch (SQLException | ClassNotFoundException e) {
        }
    }

    private static void createResourceTable() {
        try (Connection connection = ResourceDB.connect();
             Statement statement = connection.createStatement()) {
            String query = "create table resource\n" +
                    "(\n" +
                    "    resource_id     bigint generated by default as identity\n" +
                    "        constraint resource_pk\n" +
                    "            primary key,\n" +
                    "    resource_name   text   not null,\n" +
                    "    created_at      date   not null,\n" +
                    "    organization_id bigint not null \n" +
                    "        constraint resource_organizations_organization_id_fk\n" +
                    "            references organizations,\n" +
                    "    operating_system text not null,\n" +
                    "    resource_type text not null,\n" +
                    "    CONSTRAINT chk_state check (resource_type = 'ON-PREM' OR resource_type = 'CLOUD'),\n" +
                    "    CONSTRAINT chk_os check (operating_system = 'LINUX' OR operating_system = 'WINDOWS' OR operating_system = 'MAC')\n" +
                    ");\n" +
                    "\n" +
                    "alter table resource\n" +
                    "    owner to postgres;\n" +
                    "\n";
            statement.executeQuery(query);
        } catch (SQLException | ClassNotFoundException e) {
        }
    }

    private static void dropTables(){
        dropVulns();
        dropResources();
        dropOrganizations();
    }
    private static void dropVulns() {
        try (Connection connection = ResourceDB.connect();
             Statement statement = connection.createStatement()) {
            statement.executeQuery("DROP TABLE IF EXISTS vulnerabilities");
        } catch (SQLException | ClassNotFoundException e) {
        }
    }
    private static void dropResources() {
        try (Connection connection = ResourceDB.connect();
             Statement statement = connection.createStatement()) {
            statement.executeQuery("DROP TABLE IF EXISTS resource");
        } catch (SQLException | ClassNotFoundException e) {
        }
    }
    private static void dropOrganizations() {
        try (Connection connection = ResourceDB.connect();
             Statement statement = connection.createStatement()) {
            statement.executeQuery("DROP TABLE IF EXISTS organizations");
        } catch (SQLException | ClassNotFoundException e) {
        }
    }
}
