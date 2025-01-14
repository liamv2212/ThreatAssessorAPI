package com.example.threatassessorapi;

import com.google.gson.Gson;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;

public class ResourcesControllerTest {
    @Test
    public void testGetResources_no_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<Resource> resources = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
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
        if(resources.size() > 0){
            System.out.println("Get All Resources... Pass");
        }
        else             System.out.println("Get All Resources... Fail");
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
        if(resources.size() > 0){
            System.out.println("Get All Resources... Pass");
        }
        else System.out.println("Get All Resources... Fail");
    }

    @Test
    public void testGetResources_with_OrgID_InvalidOS() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<Resource> resources = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/?org_id=1&OS=l1nux"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
    }

    @Test
    public void testGetResources_with_OrgID_OS_InvalidResourceType() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<Resource> resources = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/?org_id=1&OS=linux&resource_type=cloud"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
    }

    @Test
    public void testGetResourceVulnerabilities_no_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
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
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
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
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
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
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
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
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
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
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
    }

    @Test
    public void testGetResourceVulnerabilities_with_endDate_no_startDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
    }

    @Test
    public void testGetResourceVulnerabilities_InvalidOS() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?OS=l1nux?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
    }

    @Test
    public void testGetResourceVulnerabilities_InvalidResourceType() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/vulnerabilities?OS=l1nux?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
    }

    @Test
    public void testGetVulnCountForResource_no_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
    }

    @Test
    public void testGetVulnCountForResource_with_OrgID() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
    }

    @Test
    public void testGetVulnCountForResource_with_OrgID_and_startDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?start_date=1735232375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
    }

    @Test
    public void testGetVulnCountForResource_with_OrgID_and_startDate_and_endDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?start_date=1735232375000&end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        for(String resource_vulns : getResponse.body().replaceAll("[\\[\\]]", "").replaceAll("},\\{", "}+{").split("\\+")){
            ResourceVulnerability resourceVuln = gson.fromJson(resource_vulns, ResourceVulnerability.class);
            resourceVulns.add(resourceVuln);
        }
        if(resourceVulns.size() > 0){
            System.out.println("Get All Resource Vulnerabilities... Pass");
        }
        else System.out.println("Get All Resource Vulnerabilities... Fail");
    }

    @Test
    public void testGetVulnCountForResource_with_endDate_no_startDate() throws URISyntaxException, IOException, InterruptedException {
        ArrayList<ResourceVulnerability> resourceVulns = new ArrayList<>();
        Gson gson = new Gson();
        HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(new URI("http://localhost:8080/resources/1/vulnCount?end_date=1735664375000&org_id=1"))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> getResponse = httpClient.send(getRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(getResponse);
    }
}
