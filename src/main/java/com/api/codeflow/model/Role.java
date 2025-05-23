package com.api.codeflow.model;

import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Table(name = "roles")
public class Role {

    @Id
    private Long id;
    private String name;
}
