package com.example.threatassessorapi;

import java.util.Date;

public class Resource {
    private int id;
    private String name;
    private Date date;
    private int org_id;
    private String operating_system;
    private String resource_type;

    public Resource(int id, String name, Date date, int org_id, String operating_system, String resource_type) {
        this.id = id;
        this.name = name;
        this.date = date;
        this.org_id = org_id;
        this.operating_system = operating_system;
        this.resource_type = resource_type;
    }

    public Resource(String name, Date date, int org_id){
        this.name = name;
        this.date = date;
        this.org_id = org_id;
    }

    public int getId() {return id;}
    public String getType() {return name; }
    public Date getDate() {return date; }
    public int getOrg_id() { return org_id; }
    public String getOS() { return operating_system; }
    public String getResourceType() { return resource_type; }
}
