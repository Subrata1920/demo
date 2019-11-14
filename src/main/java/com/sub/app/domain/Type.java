package com.sub.app.domain;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import lombok.Data;

@Data
@Entity
@Table(name="type")
public class Type implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="type_id_pk")
	private int typeId;

	@Column(name = "type_code", nullable = false, length = 60)
	private String typeCode;

	@Column(name = "type_name", length = 60)
	private String typeName;

	@Column(name = "description")
	private String description;

	@Column(name = "updated_date")
	private Date updatedDate;

	@Column(name = "updated_by", length = 60)
	private String updatedBy;
	
	@OneToMany(mappedBy="type")
	private List<TypeDetails> typeDetails;
	
	@Column(name = "live", nullable = false)
	private Boolean live;
	
}
