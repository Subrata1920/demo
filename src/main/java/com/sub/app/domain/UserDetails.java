package com.sub.app.domain;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;

@Entity
@Table(name="user_details")
@Data
public class UserDetails implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	private Integer userId;
	
	private String userName;
	
	private String password;
	
	private String role;
	
	@Column(name = "enabled", columnDefinition = "boolean DEFAULT true")
	private boolean enabled = true;

	@Column(name = "credentialexpired", columnDefinition = "boolean DEFAULT false")
	private boolean credentialexpired = false;

	@Column(name = "expired", columnDefinition = "boolean DEFAULT false")
	private boolean expired = false;

	@Column(name = "locked", columnDefinition = "boolean DEFAULT false")
	private boolean locked = false;


}
