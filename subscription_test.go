package main

import (
	"fmt"
	"sync"
	"testing"
)

func TestPublishIsNonblocking(t *testing.T) {
	pb := NewPubSub()
	subscriber := pb.Subscribe()
	defer subscriber.Close()

	for i := 0; i < 100; i++ {
		pb.Publish(fmt.Sprintf("hello, world! %d", i))
	}

	lastMessage := <-subscriber.C
	if lastMessage != "hello, world! 99" {
		t.Errorf("Got incorrect last message: %s", lastMessage)
	}
}

func TestSubscribeAlwaysSeesFirstMessage(t *testing.T) {
	// Run a publish and subscribe in parallel and verify that the message doesn't get lost

	for i := 0; i < 100; i++ {
		wg := sync.WaitGroup{}
		wg.Add(1)

		pb := NewPubSub()
		go pb.Publish("hello, world!")
		go func() {
			s := pb.Subscribe()
			defer s.Close()

			msg := <-s.C
			if msg != "hello, world!" {
				t.Errorf("Got unexpected message: %s", msg)
			}
			wg.Add(-1)
		}()

		wg.Wait()
	}
}

func TestAllSubscribersSeePublication(t *testing.T) {
	pb := NewPubSub()
	wg := sync.WaitGroup{}
	wg.Add(100)

	for i := 0; i < 100; i++ {
		go func() {
			s := pb.Subscribe()
			defer s.Close()

			msg := <-s.C
			if msg != "hello, world!" {
				t.Errorf("Got unexpected message: %s", msg)
			}
			wg.Add(-1)
		}()
	}

	pb.Publish("hello, world!")
	wg.Wait()
}

func TestClosedSubscriberDoesNotGetPublication(t *testing.T) {
	pb := NewPubSub()
	s1 := pb.Subscribe()
	defer s1.Close()
	s2 := pb.Subscribe()
	defer s2.Close()

	pb.Publish("msg1")
	if msg := <-s1.C; msg != "msg1" {
		t.Errorf("Got unexpected message: %s", msg)
	}
	if msg := <-s2.C; msg != "msg1" {
		t.Errorf("Got unexpected message: %s", msg)
	}

	s1.Close()
	pb.Publish("msg2")
	if msg := <-s1.C; msg != nil {
		t.Errorf("Got unexpected message: %s", msg)
	}
	if msg := <-s2.C; msg != "msg2" {
		t.Errorf("Got unexpected message: %s", msg)
	}
}
