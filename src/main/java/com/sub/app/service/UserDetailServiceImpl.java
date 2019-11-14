package com.sub.app.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.sub.app.domain.Events;
import com.sub.app.repository.EventsRepository;
import com.sub.app.util.Constants;

@Service
public class UserDetailServiceImpl implements UserDetailService{
	
	@Autowired
	private EventsRepository eventsRepository;

	@Override
	public ResponseEntity<String> erase() {
		eventsRepository.deleteAll();
		return new ResponseEntity<String>(Constants.ERASED, HttpStatus.OK);
	}

	@Override
	public ResponseEntity<String> addEvents(Events events) {
		Events ev = eventsRepository.findByEventId(events.getEventId());
		
		if(ev != null && ev.getEventId() == events.getEventId()) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Constants.EXISTS);
		}else {
			eventsRepository.save(events);
			return ResponseEntity.status(HttpStatus.CREATED).body(Constants.CREATED_MSG);
		}
	}

	@Override
	public ResponseEntity<List<Events>> getAllEvents() {
		return ResponseEntity.status(HttpStatus.OK).body(eventsRepository.findAllByOrderByEventIdAsc());
	}
	
	@Override
	public ResponseEntity<List<Events>> getEventsByActor() {
		// TODO Auto-generated method stub
		return null;
	}
	
}
