
// database if set that way instead.
process.env.DB_PATH = ':memory:'
process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'test-secret'
process.env.DISABLE_SCHEDULER = 'true'
