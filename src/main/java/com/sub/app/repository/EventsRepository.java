package com.sub.app.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sub.app.domain.Events;

public interface EventsRepository extends JpaRepository<Events, Integer>{

	Events findByEventId(Integer evnetId);

	List<Events> findAllByOrderByEventIdAsc();

}
