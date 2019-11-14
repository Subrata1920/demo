package com.sub.app.domain;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import lombok.Data;

@Data
@Entity
@Table(name="type_details")
public class TypeDetails implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="type_detail_id_pk")
	private Integer typeDetailId;
	
	@Column(name = "type_detail_name", length = 150)
	private String typeDetailName;
	
	@Column(name="description", length = 150)
	private String description;
	
	@Column(name = "created_by", length = 60)
	private String createdBy;
	
	@Column(name = "created_date")
	private Date createdDate;
	
	@ManyToOne
	@JoinColumn(name="type_id_fk")
	private Type type;
	
	@Column(name = "live", nullable = false)
	private Boolean live;

}
