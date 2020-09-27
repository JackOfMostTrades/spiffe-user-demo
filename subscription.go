package main

import "sync"

type Subscription struct {
	// Notifications published on the PubSub will be sent to this channel. Messages to not queue, so only the last
	// notification is guaranteed to be received.
	C chan interface{}

	closed bool
	pb     *PubSub
}

type PubSub struct {
	lastMessage      interface{}
	subscriptionsMtx sync.Mutex
	subscriptions    []*Subscription
}

func NewPubSub() *PubSub {
	return &PubSub{}
}

func (pb *PubSub) GetSubscriberCount() int {
	return len(pb.subscriptions)
}

// Publish sends the notification to all subscribers. This is guaranteed to not block.
func (pb *PubSub) Publish(notification interface{}) {
	pb.subscriptionsMtx.Lock()
	defer pb.subscriptionsMtx.Unlock()

	pb.lastMessage = notification

	for _, sub := range pb.subscriptions {
		if !sub.closed {

			// Remove any pending message on the subscription channel
			select {
			case <-sub.C:
			default:
			}

			// And then send a new notification to the channel
			sub.C <- notification
		}
	}
}

// Creates a new Subscriber that will receive notifications when Published
func (pb *PubSub) Subscribe() *Subscription {
	s := &Subscription{
		C:      make(chan interface{}, 1),
		closed: false,
		pb:     pb,
	}

	pb.subscriptionsMtx.Lock()
	defer pb.subscriptionsMtx.Unlock()
	pb.subscriptions = append(pb.subscriptions, s)
	if pb.lastMessage != nil {
		s.C <- pb.lastMessage
	}

	return s
}

// Close the subscription. The channel on the subscription will be closed and no more notifications will be sent.
func (s *Subscription) Close() {
	if s.closed {
		return
	}

	s.closed = true
	close(s.C)

	// Remove subscription from list of PubSub's subscriptions
	s.pb.subscriptionsMtx.Lock()
	defer s.pb.subscriptionsMtx.Unlock()
	for idx, sub := range s.pb.subscriptions {
		if sub == s {
			s.pb.subscriptions = append(s.pb.subscriptions[:idx], s.pb.subscriptions[idx+1:]...)
		}
	}
}
