const getState = ({ getStore, getActions, setStore }) => {
	return {
		store: {
			user: null,
			error: null,
			message: null,
			isLogged: false,
			isLoginModalOpen: (""),
			actions: [],
			demo: [
				{
					title: "FIRST",
					background: "white",
					initial: "white"
				},
				{
					title: "SECOND",
					background: "white",
					initial: "white"
				}
			]

		},
		actions: {
			// Use getActions to call a function within a fuction


			isAuthenticated: () => {
				// Devuelve el estado de isLogged directamente desde el store
				return getStore().isLogged;
			},

			login: (userData) => {
				setStore({
					isLogged: true,
					first_name: userData.first_name
				});
			},
			
			logout: () => {
				setStore({
					isLogged: false,
					first_name: null
				});
			},

			// Abrir y cerrar modal
			openLoginModal: () => {
				setStore({ isLoginModalOpen: true });
			},
		
			closeLoginModal: () => {
				setStore({ isLoginModalOpen: false });
			},


			getMessage: async () => {
				try {
					// fetching data from the backend
					const resp = await fetch(process.env.BACKEND_URL + "/api/hello")
					const data = await resp.json()
					setStore({ message: data.message })
					// don't forget to return something, that is how the async resolves
					return data;
				} catch (error) {
					console.log("Error loading message from backend", error)
				}
			},

			changeColor: (index, color) => {
				//get the store
				const store = getStore();

				//we have to loop the entire demo array to look for the respective index
				//and change its color
				const demo = store.demo.map((elm, i) => {
					if (i === index) elm.background = color;
					return elm;
				});

				//reset the global store
				setStore({ demo: demo });
			}
		}
	};
};

export default getState;