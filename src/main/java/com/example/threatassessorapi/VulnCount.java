package com.example.threatassessorapi;

import java.time.LocalDate;
import java.util.Date;

public class VulnCount {
    private int resource_id;
    private String resource_name;
    private int vulnCount;
    private Date partition_date;

    public VulnCount(int resourceId, String resourceType, int vulnCount, Date partition_date) {
        this.resource_id = resourceId;
        this.resource_name = resourceType;
        this.vulnCount = vulnCount;
        this.partition_date = partition_date;
    }
    public int getResource_id() {return resource_id;}
    public String getResource_type() {return resource_name;}
    public int getVulnCount() {return vulnCount;}
    public Date getPartition_date() {return partition_date;}
}
