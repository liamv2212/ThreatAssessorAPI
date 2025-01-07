package com.example.threatassessorapi;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Objects;

public class SQLHelpers {
//
//    public static void main(String[] args) throws Exception {
//        Long date = 1735232375000L;
//        getDateFilter(date, null);
//    }
    public static String getDateFilter(Long startDate, Long endDate) throws Exception {
        String rangeQuery = "";
        if (startDate != null && endDate != null) {
            LocalDate start, end;
            Instant startInstant = Instant.ofEpochMilli(startDate);
            ZoneId startZoneId = ZoneId.systemDefault();
            start = startInstant.atZone(startZoneId).toLocalDate();
            start = toMonday(start);
            Instant endInstant = Instant.ofEpochMilli(endDate);
            ZoneId endZoneId = ZoneId.systemDefault();
            end = endInstant.atZone(endZoneId).toLocalDate();
            end = toMonday(end);

            rangeQuery = " AND partition_date BETWEEN '" + start + "' AND '" + end + "'";
        }
        if (startDate != null && endDate == null) {
            LocalDate start;
            Instant instant = Instant.ofEpochMilli(startDate);
            ZoneId zoneId = ZoneId.systemDefault();
            start = instant.atZone(zoneId).toLocalDate();
            start = toMonday(start);
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


    public static LocalDate toMonday(LocalDate date) {
        switch (date.getDayOfWeek()) {
            case TUESDAY -> {
                return date.minusDays(1);
            }
            case WEDNESDAY -> {
                return date.minusDays(2);
            }
            case THURSDAY -> {
                return date.minusDays(3);
            }
            case FRIDAY -> {
                return date.minusDays(4);
            }
            case SATURDAY -> {
                return date.minusDays(5);
            }
            case SUNDAY -> {
                return date.minusDays(6);
            }
            default -> {
                return date;
            }
        }
    }
}
