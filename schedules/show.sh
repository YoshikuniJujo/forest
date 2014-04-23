#!/bin/sh

marge-schedule \
	../../forest/schedules/item_list \
	../../yagrumo/schedules/item_list \
	../../sloth/schedules/item_list -- \
	../../forest/schedules/schedule.schd \
	../../yagrumo/schedules/schedule.schd \
	../../sloth/schedules/schedule.schd \
	../../yagrumo/schedules/lectures.schd
