import axios from 'axios';
import io from 'socket.io-client';
import { create } from 'ipfs-http-client';
import * as ed25519 from '@noble/ed25519';

const apiClient = axios.create({
    baseURL: process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:3000/api',
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json',
    },
});

const socket = io(process.env.NEXT_PUBLIC_WS_BASE_URL || 'ws://localhost:3000', {
    transports: ['websocket'],
});

socket.on('connect', () => {
    console.log('Connected to WebSocket server');
});

socket.on('disconnect', () => {
    console.log('Disconnected from WebSocket server');
});

const ipfs = create({
    host: 'ipfs.infura.io',
    port: 5001,
    protocol: 'https',
});

export const fetchProducts = async (categoryId: string) => {
    try {
        const response = await apiClient.get(`/products?category=${categoryId}`);
        return response.data;
    } catch (error) {
        console.error('Error fetching products:', error);
        throw error;
    }
};

export const fetchProductDetails = async (productId: string) => {
    try {
        const response = await apiClient.get(`/products/${productId}`);
        return response.data;
    } catch (error) {
        console.error('Error fetching product details:', error);
        throw error;
    }
};

export const addProduct = async (productData: any) => {
    try {
        const response = await apiClient.post('/products', productData);
        return response.data;
    } catch (error) {
        console.error('Error adding product:', error);
        throw error;
    }
};

export const subscribeToUpdates = (event: string, callback: (data: any) => void) => {
    socket.on(event, callback);
};

export const unsubscribeFromUpdates = (event: string) => {
    socket.off(event);
};

export const uploadToIPFS = async (file: File) => {
    try {
        const added = await ipfs.add(file);
        return added.path; // Returns the CID of the uploaded file
    } catch (error) {
        console.error('Error uploading to IPFS:', error);
        throw error;
    }
};

export const signTransaction = async (privateKey: string, message: string) => {
    try {
        const privateKeyBytes = Buffer.from(privateKey, 'hex');
        const messageBytes = Buffer.from(message, 'utf-8');
        const signature = await ed25519.sign(messageBytes, privateKeyBytes);
        return Buffer.from(signature).toString('hex');
    } catch (error) {
        console.error('Error signing transaction:', error);
        throw error;
    }
};
