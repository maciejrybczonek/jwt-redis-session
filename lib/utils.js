var _ = require("lodash"),
	jwt = require("jsonwebtoken"),
	uuid = require("uuid");

var extendSession = function (session, data) {
	_.reduce(data, function (memo, val, key) {
		if(typeof val !== "function" && key !== "id")
			memo[key] = val;
		return memo;
	}, session);
};

var serializeSession = function (session) {
	return _.reduce(session, function (memo, val, key) {
		if(typeof val !== "function" && key !== "id")
			memo[key] = val;
		return memo;
	}, {});
};

// these are bound to the session
module.exports = function (options) {

	var SessionUtils = function () {};

	_.extend(SessionUtils.prototype, {

		// create a new session and return the jwt
		create: function (claims, callback) {
			if(typeof claims === "function" && !callback) {
				callback = claims;
				claims = {};
			}
			var self = this,
				sid = uuid.v4();
			var token = jwt.sign(_.extend({
				jti: sid
			}, claims || {}), options.secret, {
				algorithm: options.algorithm
			});
			var keyName = options.keyspace + (self.user ? self.user.id + ':' : '') + sid;
			options.client.setex(keyName, options.maxAge, JSON.stringify(serializeSession(self)), function (error) {
				self.id = sid;
				callback(error, token);
			});
		},

		// update the TTL on a session
		touch: function (callback) {
			var self = this;
			if(!this.id) {
				return process.nextTick(function () {
					callback(new Error("Invalid session ID"));
				});
			}
			var keyName = options.keyspace + (self.user ? self.user.id + ':' : '') + this.id;
			options.client.expire(keyName, options.maxAge, callback);
		},

		// update a session's data, update the ttl
		update: function (callback) {
			var self = this;
			if(!this.id) {
				return process.nextTick(function () {
					callback(new Error("Invalid session ID"));
				});
			}
			var keyName = options.keyspace + (self.user ? self.user.id + ':' : '') + this.id;
			options.client.setex(keyName, options.maxAge, JSON.stringify(serializeSession(this)), callback);
		},

		// reload a session data from redis
		reload: function (callback) {
			var self = this;
			if(!this.id) {
				return process.nextTick(function () {
					callback(new Error("Invalid session ID"));
				});
			}

			var keyName = options.keyspace + (self.user ? self.user.id + ':' : '') + this.id;
			options.client.get(keyName, function (error, resp) {
				if(error)
					return callback(error);
				try {
					resp = JSON.parse(resp);
				} catch(e) {
					return callback(e);
				}
				extendSession(self, resp);
				callback();
			});
		},

		// destroy a session
		destroy: function (callback) {
			var self = this;
			if(!this.id) {
				return process.nextTick(function () {
					callback(new Error("Invalid session ID"));
				});
			}
			var keyName = options.keyspace + (self.user ? self.user.id + ':' : '') + this.id;
			options.client.del(keyName, callback);
		},

		toJSON: function () {
			return serializeSession(this);
		},

		// destroy all sessions for specific user
		purge: function (userId, callback) {
			options.client.eval("return redis.call('del', 'defaultKey', unpack(redis.call('keys', ARGV[1])))", 0, options.keyspace + userId + ":*", function (error) {
				if(error)
					return callback(error);
				callback();
			});
		}

	});

	return SessionUtils;
};
