package com.example.threatassessorapi;

public class VulnCount {
    private int resource_id;
    private String resource_name;
    private int vulnCount;

    public VulnCount(int resourceId, String resourceType, int vulnCount) {
        this.resource_id = resourceId;
        this.resource_name = resourceType;
        this.vulnCount = vulnCount;
    }
    public int getResource_id() {return resource_id;}
    public String getResource_type() {return resource_name;}
    public int getVulnCount() {return vulnCount;}
}
