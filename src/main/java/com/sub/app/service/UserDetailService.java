package com.sub.app.service;

import java.util.List;

import org.springframework.http.ResponseEntity;

import com.sub.app.domain.Events;

public interface UserDetailService {

	ResponseEntity<String> erase();

	ResponseEntity<String> addEvents(Events events);

	ResponseEntity<List<Events>> getAllEvents();

	ResponseEntity<List<Events>> getEventsByActor();
	
}
