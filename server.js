const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET_KEY = '2uJ#4^!x78E@pNqR';
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

const uri = 'mongodb+srv://chelsea:<password>@pollingapp.coxgyqi.mongodb.net/pollingApp?retryWrites=true&w=majority';
const password = 'Lucy1984';
const connectionString = uri.replace('<password>', encodeURIComponent(password));

const client = new MongoClient(connectionString);

client.connect((err) => {
    if (err) {
        console.error('Error connecting to MongoDB:', err);
        return;
    }
    console.log('Connected to MongoDB server');
});

// Admin user registration endpoint
app.post('/api/admin/register', async (req, res) => {
    try {
        const { name, username, email, password } = req.body;

        const existingAdmin = await client.db('pollingApp').collection('admins').findOne({ username });
        if (existingAdmin) {
            return res.status(400).json({ message: 'Admin username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await client.db('pollingApp').collection('admins').insertOne({ name, username, email, password: hashedPassword });

        res.status(201).json({ message: 'Admin user registered successfully' });
    } catch (error) {
        console.error('Error registering admin user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const admin = await client.db('pollingApp').collection('admins').findOne({ username });
        if (!admin) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const passwordMatch = await bcrypt.compare(password, admin.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const token = jwt.sign({ username: admin.username }, JWT_SECRET_KEY, { expiresIn: '1h' });

        res.status(200).json({ token });
    } catch (error) {
        console.error('Error logging in admin:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Admin user password change endpoint
app.put('/api/admin/change-password', async (req, res) => {
    try {
        const { username, oldPassword, newPassword } = req.body;

        const admin = await client.db('pollingApp').collection('admins').findOne({ username });
        if (!admin) {
            return res.status(400).json({ message: 'Admin user not found' });
        }

        const passwordMatch = await bcrypt.compare(oldPassword, admin.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid old password' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        await client.db('pollingApp').collection('admins').updateOne(
            { username },
            { $set: { password: hashedNewPassword } }
        );

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error changing admin password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Admin user email change endpoint
app.put('/api/admin/change-email', async (req, res) => {
    try {
        const { username, password, newEmail } = req.body;

        const admin = await client.db('pollingApp').collection('admins').findOne({ username });
        if (!admin) {
            return res.status(400).json({ message: 'Admin user not found' });
        }

        const passwordMatch = await bcrypt.compare(password, admin.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        await client.db('pollingApp').collection('admins').updateOne(
            { username },
            { $set: { email: newEmail } }
        );

        res.status(200).json({ message: 'Email updated successfully' });
    } catch (error) {
        console.error('Error changing admin email:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// User registration endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { name, username, email, password, yearOfBirth } = req.body;

        const existingUser = await client.db('pollingApp').collection('users').findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await client.db('pollingApp').collection('users').insertOne({ name, username, email, password: hashedPassword, yearOfBirth });

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await client.db('pollingApp').collection('users').findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        res.status(200).json({ message: 'User logged in successfully' });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// User password change endpoint
app.put('/api/change-password', async (req, res) => {
    try {
        const { username, oldPassword, newPassword } = req.body;

        const user = await client.db('pollingApp').collection('users').findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        console.log('Retrieved hashed password from the database:', user.password);
        console.log('Old Password provided in the request body:', oldPassword);

        const passwordMatch = await bcrypt.compare(oldPassword, user.password);
        console.log('Result of password comparison:', passwordMatch);

        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid old password' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        await client.db('pollingApp').collection('users').updateOne(
            { username },
            { $set: { password: hashedNewPassword } }
        );

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error changing user password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// User password reset request endpoint
app.post('/api/reset-password-request', async (req, res) => {
    try {
        const { username, email, yearOfBirth } = req.body;

        const user = await client.db('pollingApp').collection('users').findOne({ username, email, yearOfBirth });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username, email, or year of birth' });
        }

        const temporaryPassword = generateTemporaryPassword();

        const hashedNewPassword = await bcrypt.hash(temporaryPassword, 10);
        await client.db('pollingApp').collection('users').updateOne(
            { username },
            { $set: { password: hashedNewPassword } }
        );

        res.status(200).json({ temporaryPassword });
    } catch (error) {
        console.error('Error requesting password reset:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Placeholder function to generate a temporary password
function generateTemporaryPassword() {
    const temporaryPassword = Math.random().toString(36).substr(2, 8);
    return temporaryPassword;
}

// User email change endpoint
app.put('/api/change-email', async (req, res) => {
    try {
        const { username, password, newEmail } = req.body;

        const user = await client.db('pollingApp').collection('users').findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        await client.db('pollingApp').collection('users').updateOne(
            { username },
            { $set: { email: newEmail } }
        );

        res.status(200).json({ message: 'Email updated successfully' });
    } catch (error) {
        console.error('Error changing user email:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});