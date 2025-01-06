package com.example.threatassessorapi;

import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Objects;

public class SQLHelpers {
    public static String getDateFilter(Long startDate, Long endDate) throws Exception {
        String rangeQuery = "";
        if (startDate != null && endDate != null) {
            LocalDate start, end;
            Instant startInstant = Instant.ofEpochMilli(startDate);
            ZoneId startZoneId = ZoneId.systemDefault();
            start = startInstant.atZone(startZoneId).toLocalDate();
            Instant endInstant = Instant.ofEpochMilli(endDate);
            ZoneId endZoneId = ZoneId.systemDefault();
            end = endInstant.atZone(endZoneId).toLocalDate();

            rangeQuery = " AND partition_date BETWEEN '" + start + "' AND '" + end + "'";
        }
        if (startDate != null && endDate == null) {
            LocalDate start;
            Instant instant = Instant.ofEpochMilli(startDate);
            ZoneId zoneId = ZoneId.systemDefault();
            start = instant.atZone(zoneId).toLocalDate();
            LocalDate end = LocalDate.now();
            rangeQuery = " AND partition_date BETWEEN '" + start + "' AND '" + end + "'";
        }
        if (startDate == null && endDate != null) {
            throw new Exception("Start Date must be specified to use End Date");
        }
        return rangeQuery;
    }

    public static String getOSFilter(String OS) throws Exception {
        if (!Objects.isNull(OS)){
            return switch (OS.toLowerCase()) {
                case "windows", "linux", "mac" -> " AND operating_system =  '" + OS.toUpperCase() + "'";
                default -> throw new Exception("Unknown OS: " + OS.toUpperCase());
            };
        }
        else return "";
    }

    public static String getResourceTypeFilter(String resource_type) throws Exception {
        if(!Objects.isNull(resource_type)){
            return switch (resource_type.toLowerCase()){
            case "on-prem", "cloud" -> " AND resource_type = '" + resource_type.toUpperCase() + "'";
            default -> throw new Exception("Unknown resource_type: " + resource_type.toUpperCase());
            };
        }
        else return "";
    }
}
