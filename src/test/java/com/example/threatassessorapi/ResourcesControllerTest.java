package com.example.threatassessorapi;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class ResourcesControllerTest {
    @Test
    public void testGetResources_no_OrgID() throws URISyntaxException, IOException, InterruptedException {

        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetResources_with_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<Resource> resources = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String userString : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            Resource resource = gson.fromJson(userString, Resource.class);
            resources.add(resource);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resources.size(), 0);
    }

    @Test
    public void testGetResources_with_OrgID_OS() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<Resource> resources = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/?org_id=1&OS=linux"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String userString : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            Resource resource = gson.fromJson(userString, Resource.class);
            resources.add(resource);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resources.size(), 0);
    }

    @Test
    public void testGetResources_with_OrgID_InvalidOS() throws URISyntaxException, IOException, InterruptedException {

        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/?org_id=1&OS=l1nux"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetResources_with_OrgID_OS_InvalidResourceType() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/?org_id=1&OS=linux&resource_type=c1oud"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetResourceVulnerabilities_no_OrgID() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetResourceVulnerabilities_with_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);
    }

    @Test
    public void testGetResourceVulnerabilities_with_OrgID_and_startDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?start_date=1735232375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);
    }

    @Test
    public void testGetResourceVulnerabilities_with_OrgID_and_startDate_and_endDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?start_date=1735232375000&end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);
    }

    @Test
    public void testGetResourceVulnerabilities_with_OrgID_and_startDate_and_endDate_and_OS() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?start_date=1735232375000&end_date=1735664375000&org_id=1&OS=linux"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);
    }
    @Test
    public void testGetResourceVulnerabilities_with_OrgID_and_startDate_and_endDate_and_OS_and_resource_type() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?start_date=1735232375000&end_date=1735664375000&org_id=1&OS=linux&resource_type=cloud"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);
    }

    @Test
    public void testGetResourceVulnerabilities_with_endDate_no_startDate() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetResourceVulnerabilities_InvalidOS() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?OS=l1nux?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetResourceVulnerabilities_InvalidResourceType() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?OS=l1nux?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetVulnCountForResource_no_OrgID() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testGetVulnCountForResource_with_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);
    }

    @Test
    public void testGetVulnCountForResource_with_OrgID_and_startDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?start_date=1735232375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);
    }

    @Test
    public void testGetVulnCountForResource_with_OrgID_and_startDate_and_endDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(resourceVulns.size(), 0);    }

    @Test
    public void testGetVulnCountForResource_with_endDate_no_startDate() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testCountAllResourceVulns_no_OrgID() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testCountAllResourceVulns_with_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }

    @Test
    public void testCountAllResourceVulns_with_OrgID_And_StartDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }
    @Test
    public void testCountAllResourceVulns_with_OrgID_StartDate_And_EndDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }

    @Test
    public void testCountAllResourceVulns_with_OrgID_StartDate_EndDate_And_OS() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1&OS=linux"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }
    @Test
    public void testCountAllResourceVulns_with_OrgID_StartDate_EndDate_OS_And_ResourceType() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1&OS=linux&resource_type=cloud"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }

    @Test
    public void testCountAllResourceVulns_with_invalid_OS() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?&org_id=1&OS=l1nux"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testCountAllResourceVulns_with_invalid_ResourceType() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?&org_id=1&resource_type=c1oud"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testCountAllResources_no_OrgID() throws URISyntaxException, IOException, InterruptedException {

        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testCountAllResources_with_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }

    @Test
    public void testCountAllResources_with_OrgID_And_StartDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }

    @Test
    public void testCountAllResources_with_OrgID_StartDate_And_EndDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }

    @Test
    public void testCountAllResources_with_OrgID_StartDate_EndDate_And_OS() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1&OS=linux"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }
    @Test
    public void testCountAllResources_with_OrgID_StartDate_EndDate_OS_And_ResourceType() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<VulnCount> vulnCounts = new ArrayList<>();
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd").create();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1&OS=linux&resource_type=cloud"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            VulnCount vulnCount = gson.fromJson(resource_vulns, VulnCount.class);
            vulnCounts.add(vulnCount);
        }
        assertEquals(getResponse.statusCode(), 200);
        assertNotEquals(vulnCounts.size(), 0);
    }

    @Test
    public void testCountAllResources_endDate_no_startDate() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testCountAllResources_invalid_OS() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?OS=l1nux&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }

    @Test
    public void testCountAllResources_invalid_resource_type() throws URISyntaxException, IOException, InterruptedException {
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnCount?resource_type=c1ous&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(getResponse.statusCode(), 400);
    }
}
